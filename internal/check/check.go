// Package check dispatches read-only checks against a remote host to
// determine whether a rule's desired state is already satisfied.
// Each check method maps to one [api.Check.Method] string; multi-check
// composition uses AND semantics via the [api.Check.Checks] slice.
package check

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Hanalyx/kensa/api"
)

// compareValue reports whether got satisfies (comparator) expected.
//
// comparator defaults to "==" when empty. For "=="/"!=" the eqInsensitive flag
// selects case-insensitive equality (config_value, which has always used
// strings.EqualFold) vs exact equality (sysctl_value) — preserving the
// existing per-method asymmetry. For the numeric comparators (<,<=,>,>=) both
// operands are parsed as int64; if either side is non-numeric the comparison
// returns false (the check is non-compliant, not an error). The set of valid
// comparators is enforced at rule-load by the value-domain validator, so an
// unrecognized operator here is defensively treated as non-compliant.
func compareValue(got, expected, comparator string, eqInsensitive bool) bool {
	switch comparator {
	case "", "==":
		if eqInsensitive {
			return strings.EqualFold(got, expected)
		}
		return got == expected
	case "!=":
		if eqInsensitive {
			return !strings.EqualFold(got, expected)
		}
		return got != expected
	case "<", "<=", ">", ">=":
		g, gerr := strconv.ParseInt(strings.TrimSpace(got), 10, 64)
		e, eerr := strconv.ParseInt(strings.TrimSpace(expected), 10, 64)
		if gerr != nil || eerr != nil {
			return false
		}
		switch comparator {
		case "<":
			return g < e
		case "<=":
			return g <= e
		case ">":
			return g > e
		default: // ">="
			return g >= e
		}
	default:
		return false
	}
}

// Run dispatches chk to the appropriate check method and returns a [Result]
// carrying the verdict, a human-readable detail, and the structured
// observation evidence (one [api.CheckEvidence] per command executed). When
// chk.Checks is non-empty the check uses AND composition: all child checks
// must pass and their evidence is concatenated. Individual method dispatch
// errors are returned as errors; transport-level failures are surfaced via the
// error return rather than the bool.
//
// Evidence is captured by wrapping transport in a recorder before dispatch, so
// the individual check functions need no change — they call transport.Run as
// before and the recorder captures what they ran and observed.
func Run(ctx context.Context, transport api.Transport, chk api.Check) (Result, error) {
	if len(chk.Checks) > 0 {
		return runMulti(ctx, transport, chk.Checks)
	}
	rec := &recordingTransport{inner: transport}
	passed, detail, err := dispatch(ctx, rec, chk)
	return Result{Passed: passed, Detail: detail, Evidence: buildEvidence(chk, rec.cmds)}, err
}

// dispatch routes a single check to its method implementation. The check
// functions are unchanged; they each return (passed, detail, error).
func dispatch(ctx context.Context, transport api.Transport, chk api.Check) (bool, string, error) {
	switch chk.Method {
	case "config_value":
		return checkConfigValue(ctx, transport, chk.Params)
	case "sysctl_value":
		return checkSysctlValue(ctx, transport, chk.Params)
	case "package_installed":
		return checkPackageInstalled(ctx, transport, chk.Params)
	case "package_absent":
		return checkPackageAbsent(ctx, transport, chk.Params)
	case "package_state":
		return checkPackageState(ctx, transport, chk.Params)
	case "dpkg_installed":
		return checkDpkgInstalled(ctx, transport, chk.Params)
	case "dpkg_absent":
		return checkDpkgAbsent(ctx, transport, chk.Params)
	case "apparmor_state":
		return checkApparmorState(ctx, transport, chk.Params)
	case "file_exists":
		return checkFileExists(ctx, transport, chk.Params)
	case "file_absent":
		return checkFileAbsent(ctx, transport, chk.Params)
	case "file_permissions", "file_permission":
		return checkFilePermissions(ctx, transport, chk.Params)
	case "file_content_match":
		return checkFileContentMatch(ctx, transport, chk.Params)
	case "file_content":
		return checkFileContent(ctx, transport, chk.Params)
	case "service_enabled":
		return checkServiceEnabled(ctx, transport, chk.Params)
	case "service_active":
		return checkServiceActive(ctx, transport, chk.Params)
	case "service_state":
		return checkServiceState(ctx, transport, chk.Params)
	case "audit_rule_exists":
		return checkAuditRuleExists(ctx, transport, chk.Params)
	case "sshd_effective_config":
		return checkSshdEffectiveConfig(ctx, transport, chk.Params)
	case "mount_option":
		return checkMountOption(ctx, transport, chk.Params)
	case "kernel_module_state":
		return checkKernelModuleState(ctx, transport, chk.Params)
	case "grub_parameter":
		return checkGrubParameter(ctx, transport, chk.Params)
	case "selinux_state":
		return checkSelinuxState(ctx, transport, chk.Params)
	case "systemd_target":
		return checkSystemdTarget(ctx, transport, chk.Params)
	case "command":
		return checkCommand(ctx, transport, chk.Params)
	default:
		return false, "", fmt.Errorf("check: unknown method %q", chk.Method)
	}
}

// runMulti executes each child check and returns Passed=true only when every
// child passes (AND semantics). Detail combines the individual details,
// separated by semicolons; Evidence concatenates every child's evidence (each
// child's Run wraps the transport in its own recorder, so commands are
// attributed to the right sub-check method).
func runMulti(ctx context.Context, transport api.Transport, checks []api.Check) (Result, error) {
	var details []string
	var evidence []api.CheckEvidence
	allPass := true
	for _, c := range checks {
		sub, err := Run(ctx, transport, c)
		if err != nil {
			return Result{}, err
		}
		evidence = append(evidence, sub.Evidence...)
		if sub.Detail != "" {
			details = append(details, sub.Detail)
		}
		if !sub.Passed {
			allPass = false
		}
	}
	return Result{Passed: allPass, Detail: strings.Join(details, "; "), Evidence: evidence}, nil
}

// stringParam extracts a required string parameter from params.
func stringParam(params api.Params, key string) (string, error) {
	v, ok := params[key]
	if !ok {
		return "", fmt.Errorf("check: missing required param %q", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("check: param %q must be a non-empty string, got %T", key, v)
	}
	return s, nil
}

// optionalStringParam extracts an optional string parameter from
// params, returning def when the key is absent or empty.
func optionalStringParam(params api.Params, key, def string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return def
}

// stringParamPresent returns the string value at key and whether the key was
// present at all — distinct from present-but-empty, which optionalStringParam
// folds into its default. A non-string value reports present with "".
func stringParamPresent(params api.Params, key string) (string, bool) {
	v, ok := params[key]
	if !ok {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

// firstLine returns the first line of s, trimmed and length-capped, for use in
// a failure detail message.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// checkConfigValue reads a config file and checks that a key's value
// matches the expected string. Params: path, key, expected, optionally
// scan_pattern (glob suffix for directory scans) and delimiter
// (default "=").
func checkConfigValue(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	path, err := stringParam(params, "path")
	if err != nil {
		return false, "", err
	}
	key, err := stringParam(params, "key")
	if err != nil {
		return false, "", err
	}
	// expected may be "" — meaning the key must be present as a bare
	// directive (no value required), e.g. "audit" in faillock.conf.
	expectedRaw, ok := params["expected"]
	if !ok {
		return false, "", fmt.Errorf("check: missing required param \"expected\"")
	}
	expected, _ := expectedRaw.(string)
	delimiter := optionalStringParam(params, "delimiter", "=")
	scanPattern := optionalStringParam(params, "scan_pattern", "")

	// Escape the key before splicing it into the grep -E pattern: config
	// keys legitimately contain regex metacharacters (e.g. rsyslog's
	// "$FileCreateMode" — $ is an end-anchor; limits.conf's "* hard core" —
	// * is a quantifier). Unescaped, such a key matches nothing, so the
	// check reports the rule non-compliant even when the line is present —
	// a wrong verdict (and a spurious rollback under the post-apply
	// re-check). This mirrors config_set, which already QuoteMeta's its key.
	keyPat := regexp.QuoteMeta(key)

	// When expected is empty, the check is a bare-key existence check:
	// the key must appear in the file as a standalone directive with no value.
	if expected == "" {
		barePattern := fmt.Sprintf(`^\s*%s\s*$`, keyPat)
		var bareCmd string
		if scanPattern != "" {
			bareCmd = fmt.Sprintf("grep -rqE %s %s/*.%s 2>/dev/null", shellQuote(barePattern), shellQuote(path), shellQuote(scanPattern))
		} else {
			bareCmd = fmt.Sprintf("grep -qE %s %s 2>/dev/null", shellQuote(barePattern), shellQuote(path))
		}
		res, err := transport.Run(ctx, bareCmd)
		if err != nil {
			return false, "", fmt.Errorf("check config_value: transport error: %w", err)
		}
		if res.ExitCode != 0 {
			return false, fmt.Sprintf("config_value: bare key %q not found in %s", key, path), nil
		}
		return true, fmt.Sprintf("config_value: bare key %q present in %s", key, path), nil
	}

	// A delimiter of " " means the file is WHITESPACE-delimited ("KEY value"
	// or "KEY\tvalue", e.g. /etc/login.defs). Match the key followed by one or
	// more whitespace chars — a literal-space char class [ :] would exclude
	// TAB and false-report a TAB-delimited key as "not found" (a wrong
	// compliance verdict). Other delimiters keep the exact char-class form.
	whitespaceDelim := delimiter == " "
	var pattern string
	if whitespaceDelim {
		pattern = fmt.Sprintf(`^\s*%s\s+`, keyPat)
	} else {
		pattern = fmt.Sprintf(`^\s*%s\s*[%s:]\s*`, keyPat, delimiter)
	}
	var cmd string
	if scanPattern != "" {
		// Directory scan: grep recursively using the scan pattern as a file glob suffix.
		cmd = fmt.Sprintf("grep -rE %s %s/*.%s 2>/dev/null", shellQuote(pattern), shellQuote(path), shellQuote(scanPattern))
	} else {
		cmd = fmt.Sprintf("grep -E %s %s 2>/dev/null", shellQuote(pattern), shellQuote(path))
	}

	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check config_value: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("config_value: key %q not found in %s", key, path), nil
	}

	// Take the first matching line and extract the value portion.
	line := strings.SplitN(res.Stdout, "\n", 2)[0]
	// Strip a leading "filename:" prefix produced by grep -r.
	if idx := strings.Index(line, ":"); idx >= 0 {
		// Only strip if the part before the colon looks like a path
		// (contains a slash).
		prefix := line[:idx]
		if strings.Contains(prefix, "/") {
			line = line[idx+1:]
		}
	}
	var got string
	if whitespaceDelim {
		// "KEY value" / "KEY\tvalue": the value is whatever follows the key.
		// The key itself may contain spaces (e.g. limits.conf "* hard core"),
		// so strip the matched key prefix rather than assuming fields[1] —
		// strings.Fields would return an interior word of a multi-word key.
		rest := strings.TrimPrefix(strings.TrimLeft(line, " \t"), key)
		got = strings.TrimSpace(rest)
		if got == "" {
			return false, fmt.Sprintf("config_value: could not parse value from line %q", line), nil
		}
	} else {
		// Split on delimiter or colon to isolate the value.
		sep := delimiter
		if !strings.Contains(line, sep) {
			sep = ":"
		}
		parts := strings.SplitN(line, sep, 2)
		if len(parts) < 2 {
			return false, fmt.Sprintf("config_value: could not parse value from line %q", line), nil
		}
		got = strings.TrimSpace(parts[1])
	}
	comparator := optionalStringParam(params, "comparator", "==")
	if !compareValue(got, expected, comparator, true) {
		return false, fmt.Sprintf("config_value: key %q: got %q, expected %s %q", key, got, comparator, expected), nil
	}
	return true, fmt.Sprintf("config_value: key %q = %q (%s %q)", key, got, comparator, expected), nil
}

// checkSysctlValue checks a kernel parameter value via sysctl -n.
// Params: key, expected.
func checkSysctlValue(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	key, err := stringParam(params, "key")
	if err != nil {
		return false, "", err
	}
	expected, err := stringParam(params, "expected")
	if err != nil {
		return false, "", err
	}

	cmd := fmt.Sprintf("sysctl -n %s", shellQuote(key))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check sysctl_value: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("sysctl_value: sysctl -n %s failed (exit %d)", key, res.ExitCode), nil
	}
	got := strings.TrimSpace(res.Stdout)
	comparator := optionalStringParam(params, "comparator", "==")
	if !compareValue(got, expected, comparator, false) {
		return false, fmt.Sprintf("sysctl_value: %s = %q, expected %s %q", key, got, comparator, expected), nil
	}
	return true, fmt.Sprintf("sysctl_value: %s = %q (%s %q)", key, got, comparator, expected), nil
}

// checkPackageInstalled checks whether a package is installed, trying
// rpm first (RHEL/EL) then dpkg (Debian/Ubuntu). Params: name.
func checkPackageInstalled(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	name, err := stringParam(params, "name")
	if err != nil {
		return false, "", err
	}
	// Try rpm first; fall back to dpkg when rpm is absent or the package
	// is not in the rpm database. This single command works on both
	// RHEL (rpm path succeeds) and Debian/Ubuntu (dpkg path succeeds).
	cmd := fmt.Sprintf(
		`rpm -q %[1]s >/dev/null 2>&1 || (command -v dpkg >/dev/null 2>&1 && dpkg -l %[1]s 2>/dev/null | grep -q '^ii')`,
		shellQuote(name),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check package_installed: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("package_installed: %s is not installed", name), nil
	}
	return true, fmt.Sprintf("package_installed: %s is installed", name), nil
}

// checkPackageAbsent checks whether a package is absent from both rpm
// and dpkg databases. Params: name.
func checkPackageAbsent(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	name, err := stringParam(params, "name")
	if err != nil {
		return false, "", err
	}
	// A package is absent only when it appears in neither rpm nor dpkg.
	// On RHEL, dpkg is absent so the second clause is always false — rpm
	// result is authoritative. On Ubuntu, rpm is absent or returns
	// nonzero for all packages, so dpkg is authoritative.
	cmd := fmt.Sprintf(
		`! rpm -q %[1]s >/dev/null 2>&1 && ! (command -v dpkg >/dev/null 2>&1 && dpkg -l %[1]s 2>/dev/null | grep -q '^ii')`,
		shellQuote(name),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check package_absent: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("package_absent: %s is installed but should be absent", name), nil
	}
	return true, fmt.Sprintf("package_absent: %s is not installed", name), nil
}

// checkDpkgInstalled checks whether a dpkg package is installed.
// Use this in Ubuntu-specific rule implementations as an explicit
// alternative to package_installed. Params: name.
func checkDpkgInstalled(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	name, err := stringParam(params, "name")
	if err != nil {
		return false, "", err
	}
	cmd := fmt.Sprintf("dpkg -l %s 2>/dev/null | grep -q '^ii'", shellQuote(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check dpkg_installed: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("dpkg_installed: %s is not installed", name), nil
	}
	return true, fmt.Sprintf("dpkg_installed: %s is installed", name), nil
}

// checkDpkgAbsent checks whether a dpkg package is NOT installed.
// Params: name.
func checkDpkgAbsent(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	name, err := stringParam(params, "name")
	if err != nil {
		return false, "", err
	}
	cmd := fmt.Sprintf("dpkg -l %s 2>/dev/null | grep -q '^ii'", shellQuote(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check dpkg_absent: transport error: %w", err)
	}
	if res.ExitCode == 0 {
		return false, fmt.Sprintf("dpkg_absent: %s is installed but should be absent", name), nil
	}
	return true, fmt.Sprintf("dpkg_absent: %s is not installed", name), nil
}

// checkApparmorState checks whether AppArmor is loaded and enforcing.
// Used on Ubuntu in place of selinux_state. Params: none required;
// optional state (default "enforcing") — "enforcing" or "loaded".
func checkApparmorState(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	want := optionalStringParam(params, "state", "enforcing")
	var cmd string
	switch want {
	case "enforcing":
		cmd = `aa-status 2>/dev/null | grep -q 'apparmor module is loaded' && [ "$(cat /sys/kernel/security/apparmor/profiles 2>/dev/null | wc -l)" -gt 0 ]`
	case "loaded":
		cmd = `aa-status 2>/dev/null | grep -q 'apparmor module is loaded'`
	default:
		return false, "", fmt.Errorf("check apparmor_state: unsupported state %q (want enforcing or loaded)", want)
	}
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check apparmor_state: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("apparmor_state: AppArmor is not %s", want), nil
	}
	return true, fmt.Sprintf("apparmor_state: AppArmor is %s", want), nil
}

// checkFileExists checks whether a path exists on the remote host.
// Params: path.
func checkFileExists(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	path, err := stringParam(params, "path")
	if err != nil {
		return false, "", err
	}
	cmd := fmt.Sprintf("[ -e %s ]", shellQuote(path))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check file_exists: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("file_exists: %s does not exist", path), nil
	}
	return true, fmt.Sprintf("file_exists: %s exists", path), nil
}

// checkFileAbsent checks whether a path does NOT exist on the remote
// host. Params: path.
func checkFileAbsent(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	path, err := stringParam(params, "path")
	if err != nil {
		return false, "", err
	}
	cmd := fmt.Sprintf("[ ! -e %s ]", shellQuote(path))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check file_absent: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("file_absent: %s exists but should be absent", path), nil
	}
	return true, fmt.Sprintf("file_absent: %s is absent", path), nil
}

// checkFilePermissions checks the permissions, and optionally the
// owner and group, of a file. Params: path, optionally mode (octal
// string like "0644"), owner, and group. At least one of mode, owner,
// or group must be specified.
func checkFilePermissions(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	path, err := stringParam(params, "path")
	if err != nil {
		return false, "", err
	}
	mode := optionalStringParam(params, "mode", "")
	owner := optionalStringParam(params, "owner", "")
	group := optionalStringParam(params, "group", "")
	if mode == "" && owner == "" && group == "" {
		return false, "", fmt.Errorf("check file_permissions: at least one of 'mode', 'owner', or 'group' is required")
	}

	cmd := fmt.Sprintf("stat -c '%%a %%U %%G' %s", shellQuote(path))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check file_permissions: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("file_permissions: stat failed for %s (exit %d)", path, res.ExitCode), nil
	}

	fields := strings.Fields(strings.TrimSpace(res.Stdout))
	if len(fields) < 3 {
		return false, fmt.Sprintf("file_permissions: unexpected stat output: %q", res.Stdout), nil
	}
	gotMode, gotOwner, gotGroup := fields[0], fields[1], fields[2]

	// Normalize: strip leading zeros from both sides for comparison.
	wantMode := strings.TrimLeft(mode, "0")
	if wantMode == "" {
		wantMode = "0"
	}
	gotModeNorm := strings.TrimLeft(gotMode, "0")
	if gotModeNorm == "" {
		gotModeNorm = "0"
	}

	var failures []string
	if mode != "" && gotModeNorm != wantMode {
		failures = append(failures, fmt.Sprintf("mode %s (want %s)", gotMode, mode))
	}
	if owner != "" && gotOwner != owner {
		failures = append(failures, fmt.Sprintf("owner %s (want %s)", gotOwner, owner))
	}
	if group != "" && gotGroup != group {
		failures = append(failures, fmt.Sprintf("group %s (want %s)", gotGroup, group))
	}
	if len(failures) > 0 {
		return false, fmt.Sprintf("file_permissions: %s: %s", path, strings.Join(failures, ", ")), nil
	}
	return true, fmt.Sprintf("file_permissions: %s mode=%s owner=%s group=%s", path, gotMode, gotOwner, gotGroup), nil
}

// checkFileContentMatch checks whether a file's content matches a
// regular expression. Params: path, pattern.
func checkFileContentMatch(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	path, err := stringParam(params, "path")
	if err != nil {
		return false, "", err
	}
	pattern, err := stringParam(params, "pattern")
	if err != nil {
		return false, "", err
	}
	cmd := fmt.Sprintf("grep -qE %s %s", shellQuote(pattern), shellQuote(path))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check file_content_match: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("file_content_match: pattern %q not found in %s", pattern, path), nil
	}
	return true, fmt.Sprintf("file_content_match: pattern %q found in %s", pattern, path), nil
}

// serviceCountsAsEnabled classifies `systemctl is-enabled` output for a
// "must be enabled" control. A unit with no [Install] section cannot be
// `enabled`, yet these states are on-by-design and satisfy the requirement:
//
//	static    — socket/bus/dependency-activated (e.g. systemd-journald on RHEL)
//	generated — created by a systemd generator (e.g. an fstab-derived mount)
//
// A naive strings.Contains(out,"enabled") FALSE-FAILs both — the
// journald-service-enabled false-FAIL on compliant RHEL hosts.
//
// `indirect` and `alias` are deliberately NOT here: per systemd, `indirect`
// means the queried unit itself is NOT [Install]-enabled (it merely has a
// non-empty Also=), and `alias` does not guarantee the target is enabled —
// counting either as enabled would turn a genuine "not enabled" FAIL into a
// false PASS. disabled, masked, and linked do NOT count as enabled.
func serviceCountsAsEnabled(status string) bool {
	switch strings.TrimSpace(status) {
	case "enabled", "enabled-runtime", "static", "generated":
		return true
	}
	return false
}

// serviceExplicitlyEnabled reports whether a unit is enabled VIA an [Install]
// section — the only states a "must be disabled" control may FAIL on. A static
// or indirect unit cannot be disabled and is not explicitly enabled, so it must
// NOT trip a "should not be enabled" assertion.
func serviceExplicitlyEnabled(status string) bool {
	switch strings.TrimSpace(status) {
	case "enabled", "enabled-runtime":
		return true
	}
	return false
}

// checkServiceEnabled checks whether a systemd service is enabled.
// Params: name.
func checkServiceEnabled(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	name, err := stringParam(params, "name")
	if err != nil {
		return false, "", err
	}
	cmd := fmt.Sprintf("systemctl is-enabled %s", shellQuote(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check service_enabled: transport error: %w", err)
	}
	out := strings.TrimSpace(res.Stdout)
	if !serviceCountsAsEnabled(out) {
		return false, fmt.Sprintf("service_enabled: %s is not enabled (status: %q)", name, out), nil
	}
	return true, fmt.Sprintf("service_enabled: %s is enabled", name), nil
}

// checkServiceActive checks whether a systemd service is active.
// Params: name.
func checkServiceActive(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	name, err := stringParam(params, "name")
	if err != nil {
		return false, "", err
	}
	cmd := fmt.Sprintf("systemctl is-active %s", shellQuote(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check service_active: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("service_active: %s is not active (exit %d)", name, res.ExitCode), nil
	}
	return true, fmt.Sprintf("service_active: %s is active", name), nil
}

// checkCommand runs an arbitrary command and checks the exit code and
// optionally the output. Params:
//
//	cmd / run           string  command to execute (required; "run" is the corpus alias)
//	expected_output /
//	  expected_stdout   string  optional output assertion: an empty value asserts
//	                            the command produced no output (the "find ... |
//	                            head -1" no-violations idiom); a non-empty value
//	                            asserts that value appears as a substring of stdout
//	expected_exit       int     optional expected exit code (default 0)
func checkCommand(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	// Accept both "cmd" (internal) and "run" (corpus convention).
	rawCmd := optionalStringParam(params, "cmd", "")
	if rawCmd == "" {
		rawCmd = optionalStringParam(params, "run", "")
	}
	if rawCmd == "" {
		return false, "", fmt.Errorf("check: missing required param \"cmd\"")
	}

	// Accept both "expected_output" and "expected_stdout" (output wins when both
	// keys are set). Key presence is read directly because an explicitly empty
	// value is a real assertion ("produced no output") distinct from the key
	// being absent — a distinction optionalStringParam cannot express.
	expectedOutput, expectOutput := stringParamPresent(params, "expected_output")
	if !expectOutput {
		expectedOutput, expectOutput = stringParamPresent(params, "expected_stdout")
	}

	// Optional expected exit code (default 0).
	expectedExit := 0
	if v, ok := params["expected_exit"]; ok {
		switch n := v.(type) {
		case int:
			expectedExit = n
		case float64:
			expectedExit = int(n)
		}
	}

	res, err := transport.Run(ctx, rawCmd)
	if err != nil {
		return false, "", fmt.Errorf("check command: transport error: %w", err)
	}
	if res.ExitCode != expectedExit {
		return false, fmt.Sprintf("command: %q exited with code %d (expected %d)", rawCmd, res.ExitCode, expectedExit), nil
	}
	if expectOutput {
		if strings.TrimSpace(expectedOutput) == "" {
			// Empty assertion: the command must have produced no output.
			if strings.TrimSpace(res.Stdout) != "" {
				return false, fmt.Sprintf("command: %q expected no output, got %q", rawCmd, firstLine(res.Stdout)), nil
			}
		} else if !strings.Contains(res.Stdout, expectedOutput) {
			return false, fmt.Sprintf("command: output does not contain %q", expectedOutput), nil
		}
	}
	return true, fmt.Sprintf("command: %q passed", rawCmd), nil
}

// checkPackageState checks package presence or absence via rpm.
// Params: name, state ("present" → installed, "absent" → not installed).
func checkPackageState(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	// Validate that 'name' is present before dispatching.
	if _, err := stringParam(params, "name"); err != nil {
		return false, "", err
	}
	state := optionalStringParam(params, "state", "present")
	if state == "absent" {
		return checkPackageAbsent(ctx, transport, params)
	}
	return checkPackageInstalled(ctx, transport, params)
}

// checkFileContent checks whether a file's content matches an expected
// literal string (not a regex). Params: path, expected_content.
func checkFileContent(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	path, err := stringParam(params, "path")
	if err != nil {
		return false, "", err
	}
	expected, err := stringParam(params, "expected_content")
	if err != nil {
		return false, "", err
	}
	// Use fgrep for literal match.
	cmd := fmt.Sprintf("grep -qF %s %s", shellQuote(expected), shellQuote(path))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check file_content: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("file_content: expected content not found in %s", path), nil
	}
	return true, fmt.Sprintf("file_content: expected content found in %s", path), nil
}

// checkServiceState checks a service's enabled and/or active state.
// Params: name, enabled (bool, optional), active (bool, optional).
// All specified conditions must pass (AND semantics).
func checkServiceState(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	name, err := stringParam(params, "name")
	if err != nil {
		return false, "", err
	}

	var details []string

	if wantEnabled, ok := params["enabled"]; ok {
		want, _ := wantEnabled.(bool)
		cmd := fmt.Sprintf("systemctl is-enabled %s", shellQuote(name))
		res, err := transport.Run(ctx, cmd)
		if err != nil {
			return false, "", fmt.Errorf("check service_state: transport error: %w", err)
		}
		out := strings.TrimSpace(res.Stdout)
		// want=enabled is satisfied by static/generated units (on-by-design, no
		// [Install]); indirect/alias are NOT (the queried unit isn't itself
		// enabled). want=disabled fails only on units enabled via an [Install]
		// section. See serviceCountsAsEnabled / serviceExplicitlyEnabled.
		if want && !serviceCountsAsEnabled(out) {
			return false, fmt.Sprintf("service_state: %s is not enabled (status: %q)", name, out), nil
		}
		if !want && serviceExplicitlyEnabled(out) {
			return false, fmt.Sprintf("service_state: %s is enabled but should not be (status: %q)", name, out), nil
		}
		enabled := "enabled"
		if !want {
			enabled = "not enabled"
		}
		details = append(details, fmt.Sprintf("%s %s", name, enabled))
	}

	if wantActive, ok := params["active"]; ok {
		want, _ := wantActive.(bool)
		cmd := fmt.Sprintf("systemctl is-active %s", shellQuote(name))
		res, err := transport.Run(ctx, cmd)
		if err != nil {
			return false, "", fmt.Errorf("check service_state: transport error: %w", err)
		}
		isActive := res.ExitCode == 0
		if want && !isActive {
			out := strings.TrimSpace(res.Stdout)
			return false, fmt.Sprintf("service_state: %s is not active (status: %q)", name, out), nil
		}
		if !want && isActive {
			return false, fmt.Sprintf("service_state: %s is active but should not be", name), nil
		}
		active := "active"
		if !want {
			active = "not active"
		}
		details = append(details, active)
	}

	return true, fmt.Sprintf("service_state: %s %s", name, strings.Join(details, ", ")), nil
}

// checkAuditRuleExists verifies that an audit rule is present in the
// effective kernel ruleset loaded by auditd. The check uses auditctl -l
// and matches on the -k key field extracted from the rule string, falling
// back to a full normalised-string search when no -k field is present.
// Params: rule (full audit rule string).
func checkAuditRuleExists(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	rule, err := stringParam(params, "rule")
	if err != nil {
		return false, "", err
	}

	res, err := transport.Run(ctx, "auditctl -l 2>/dev/null")
	if err != nil {
		return false, "", fmt.Errorf("check audit_rule_exists: transport error: %w", err)
	}
	loaded := strings.Split(res.Stdout, "\n")

	// A rule may carry several lines — e.g. a syscall control's b32 + b64
	// variants, or EPERM + EACCES pairs. Every line must be present.
	for _, line := range strings.Split(rule, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !AuditLineLoaded(line, loaded) {
			return false, fmt.Sprintf("audit_rule_exists: rule line not loaded: %s", normaliseAuditRule(line)), nil
		}
	}
	return true, "audit_rule_exists: all rule lines present in loaded ruleset", nil
}

// AuditLineLoaded reports whether a single audit rule line is present in the
// loaded ruleset (auditctl -l lines). It matches on the line's distinguishing
// fields rather than a literal compare, because auditctl reorders/normalises
// output: auid!=unset -> auid!=-1, "-k key" -> "-F key=key", and syscall lists
// are re-sorted. Matching only on -k would be a false pass whenever several
// rules share a key (the Ubuntu usergroup_modification / perm_chng / priv_cmd /
// module_chng clusters all do).
//
// Exported so the audit_rule_set handler's shell-transport rollback can reuse
// the exact same matcher for its post-reboot honesty verdict — a full-line
// string compare there wrongly missed normalised syscall rules.
func AuditLineLoaded(rule string, loaded []string) bool {
	// Watch rules ("-w <path> -p <perms> -k <key>") print verbatim: full match.
	if strings.HasPrefix(rule, "-w") {
		norm := normaliseAuditRule(rule)
		for _, l := range loaded {
			if normaliseAuditRule(l) == norm {
				return true
			}
		}
		return false
	}

	// Syscall / exec rules: match on the distinguishing fields the rule carries.
	archTok, hasArch := auditFToken(rule, "arch")
	pathTok, hasPath := auditFToken(rule, "path")
	permTok, hasPerm := auditFToken(rule, "perm")
	exitTok, hasExit := auditFToken(rule, "exit")
	key := extractAuditKey(rule)
	want := auditSyscallSet(rule)
	hasDistinguisher := hasArch || hasPath || hasExit || len(want) > 0

	for _, l := range loaded {
		if hasArch && !strings.Contains(l, archTok) {
			continue
		}
		if hasPath && !strings.Contains(l, pathTok) {
			continue
		}
		if hasPerm && !strings.Contains(l, permTok) {
			continue
		}
		if hasExit && !strings.Contains(l, exitTok) {
			continue
		}
		if key != "" && !strings.Contains(l, "-k "+key) && !strings.Contains(l, "key="+key) {
			continue
		}
		if len(want) > 0 && !sameStringSet(want, auditSyscallSet(l)) {
			continue
		}
		if !auidTokensPresent(rule, l) {
			continue
		}
		// With no distinguishing field at all, fall back to a full-line compare
		// so a bare keyed rule can't be satisfied by an unrelated line.
		if !hasDistinguisher && normaliseAuditRule(l) != normaliseAuditRule(rule) {
			continue
		}
		return true
	}
	return false
}

// auidTokensPresent reports whether every auid filter in the rule appears in
// the loaded line. The auid filters (auid>=1000, auid=0, auid!=unset)
// distinguish otherwise-identical syscall lines — e.g. the setxattr control's
// auid>=1000 and auid=0 variants. auditctl -l prints auid!=unset as auid!=-1,
// so normalise before comparing.
func auidTokensPresent(rule string, loadedLine string) bool {
	fields := strings.Fields(rule)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "-F" || !strings.HasPrefix(fields[i+1], "auid") {
			continue
		}
		tok := fields[i+1]
		if tok == "auid!=unset" {
			tok = "auid!=-1"
		}
		if !strings.Contains(loadedLine, tok) {
			return false
		}
	}
	return true
}

// auditSyscallSet returns the set of syscalls named in a rule's "-S a,b,c"
// tokens (auditctl -l re-sorts the list, so compare as a set, not a string).
func auditSyscallSet(rule string) map[string]bool {
	set := map[string]bool{}
	fields := strings.Fields(rule)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "-S" {
			for _, sc := range strings.Split(fields[i+1], ",") {
				if sc != "" {
					set[sc] = true
				}
			}
		}
	}
	return set
}

// sameStringSet reports whether two string sets are equal.
func sameStringSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// extractAuditKey returns the value following -k in an audit rule string,
// or empty string if none is present.
func extractAuditKey(rule string) string {
	fields := strings.Fields(rule)
	for i, f := range fields {
		if f == "-k" && i+1 < len(fields) {
			return fields[i+1]
		}
		if strings.HasPrefix(f, "-k") && len(f) > 2 {
			return f[2:]
		}
	}
	return ""
}

// auditFToken returns the "-F <field>=<value>" token for the named field in an
// audit rule (e.g. auditFToken(rule, "path") -> `-F path=/usr/bin/sudo`, true),
// or ("", false) if the field is absent. The token is matched verbatim against
// auditctl -l output, which preserves "-F path=" / "-F perm=".
func auditFToken(rule, field string) (string, bool) {
	fields := strings.Fields(rule)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "-F" && strings.HasPrefix(fields[i+1], field+"=") {
			return "-F " + fields[i+1], true
		}
	}
	return "", false
}

// normaliseAuditRule collapses whitespace in a rule string for comparison.
func normaliseAuditRule(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

// checkSshdEffectiveConfig checks a key's value in the effective sshd
// configuration as reported by `sshd -T`. Params: key, expected.
func checkSshdEffectiveConfig(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	key, err := stringParam(params, "key")
	if err != nil {
		return false, "", err
	}
	expected, err := stringParam(params, "expected")
	if err != nil {
		return false, "", err
	}

	// sshd -T dumps key value pairs (lowercase keys), one per line.
	pattern := fmt.Sprintf(`^%s `, strings.ToLower(key))
	cmd := fmt.Sprintf("sshd -T 2>/dev/null | grep -i %s", shellQuote(pattern))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check sshd_effective_config: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("sshd_effective_config: key %q not found in sshd -T output", key), nil
	}

	line := strings.TrimSpace(strings.SplitN(res.Stdout, "\n", 2)[0])
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return false, fmt.Sprintf("sshd_effective_config: could not parse value from %q", line), nil
	}
	got := strings.TrimSpace(parts[1])
	if !strings.EqualFold(got, expected) {
		return false, fmt.Sprintf("sshd_effective_config: %s = %q, expected %q", key, got, expected), nil
	}
	return true, fmt.Sprintf("sshd_effective_config: %s = %q", key, got), nil
}

// checkMountOption verifies that a mount point has all required mount
// options set. Params: mount_point (string), options ([]interface{} of strings).
func checkMountOption(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	mp, err := stringParam(params, "mount_point")
	if err != nil {
		return false, "", err
	}
	opts, err := stringSliceParam(params, "options")
	if err != nil {
		return false, "", err
	}

	cmd := fmt.Sprintf("findmnt -n -o OPTIONS %s 2>/dev/null", shellQuote(mp))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check mount_option: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("mount_option: %s is not mounted", mp), nil
	}

	// findmnt returns comma-separated options; split into a set.
	present := make(map[string]bool)
	for _, o := range strings.Split(strings.TrimSpace(res.Stdout), ",") {
		// Strip =value suffix for flag-only checks (e.g. "rw" not "rw=1").
		present[strings.SplitN(strings.TrimSpace(o), "=", 2)[0]] = true
	}

	var missing []string
	for _, want := range opts {
		if !present[want] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		return false, fmt.Sprintf("mount_option: %s missing options: %s", mp, strings.Join(missing, ", ")), nil
	}
	return true, fmt.Sprintf("mount_option: %s has required options %s", mp, strings.Join(opts, ", ")), nil
}

// checkKernelModuleState checks whether a kernel module is disabled or
// blacklisted. Params: name, state ("disabled" or "blacklisted").
//
// "disabled" means modprobe would refuse to load it (install /bin/true or
// similar in modprobe.d). "blacklisted" means it appears in a blacklist
// directive. Both states imply the module is not currently loaded.
func checkKernelModuleState(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	name, err := stringParam(params, "name")
	if err != nil {
		return false, "", err
	}
	state := optionalStringParam(params, "state", "disabled")

	// Check that the module is not currently loaded.
	lsmodCmd := fmt.Sprintf("lsmod 2>/dev/null | grep -qw %s", shellQuote(name))
	res, err := transport.Run(ctx, lsmodCmd)
	if err != nil {
		return false, "", fmt.Errorf("check kernel_module_state: transport error: %w", err)
	}
	if res.ExitCode == 0 {
		return false, fmt.Sprintf("kernel_module_state: module %s is currently loaded", name), nil
	}

	switch state {
	case "blacklisted":
		cmd := fmt.Sprintf(`grep -rq 'blacklist\s\+%s' /etc/modprobe.d/ 2>/dev/null`, name)
		res, err := transport.Run(ctx, cmd)
		if err != nil {
			return false, "", fmt.Errorf("check kernel_module_state: transport error: %w", err)
		}
		if res.ExitCode != 0 {
			return false, fmt.Sprintf("kernel_module_state: module %s is not blacklisted in /etc/modprobe.d/", name), nil
		}
		return true, fmt.Sprintf("kernel_module_state: %s is blacklisted and not loaded", name), nil
	default: // "disabled"
		// A module is effectively "not available" when modprobe would not load
		// it. `modprobe -n --show-depends <mod>` prints either:
		//   - `install /bin/true` or `install /bin/false` — an install override
		//     redirects the load to a no-op (both forms are used by CIS/STIG
		//     hardening; this check must accept EITHER), or
		//   - a "... not found ..." error — the module is absent from the kernel
		//     tree and cannot be loaded at all, which satisfies "not available",
		//   - `insmod /lib/modules/.../<mod>.ko` lines — the module IS loadable.
		// Match in Go (not a shell `grep`) so both no-op forms and the not-found
		// case are recognized and the logic is unit-testable.
		cmd := fmt.Sprintf("modprobe -n --show-depends %s 2>&1", shellQuote(name))
		res, err := transport.Run(ctx, cmd)
		if err != nil {
			return false, "", fmt.Errorf("check kernel_module_state: transport error: %w", err)
		}
		out := res.Stdout
		if strings.Contains(out, "install /bin/true") || strings.Contains(out, "install /bin/false") {
			return true, fmt.Sprintf("kernel_module_state: %s is disabled (install no-op) and not loaded", name), nil
		}
		if strings.Contains(out, "not found") {
			return true, fmt.Sprintf("kernel_module_state: %s is not available (module not present) and not loaded", name), nil
		}
		return false, fmt.Sprintf("kernel_module_state: module %s is loadable (no install /bin/true|/bin/false override)", name), nil
	}
}

// checkGrubParameter checks that a kernel command-line parameter is set
// to the expected value. Checks both /proc/cmdline (running kernel) and
// /etc/default/grub (persistent configuration). Params: key, expected.
func checkGrubParameter(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	key, err := stringParam(params, "key")
	if err != nil {
		return false, "", err
	}
	expected, err := stringParam(params, "expected")
	if err != nil {
		return false, "", err
	}

	// Check running kernel cmdline first.
	needle := key + "=" + expected
	needleFlag := key // for boolean params like "audit=1" vs bare "audit"

	cmdlineCmd := "cat /proc/cmdline 2>/dev/null"
	res, err := transport.Run(ctx, cmdlineCmd)
	if err != nil {
		return false, "", fmt.Errorf("check grub_parameter: transport error: %w", err)
	}
	cmdline := strings.TrimSpace(res.Stdout)
	runningOK := containsCmdlineParam(cmdline, needleFlag, expected)

	// Check persistent GRUB configuration.
	grubCmd := `grep -E 'GRUB_CMDLINE_LINUX' /etc/default/grub 2>/dev/null`
	res, err = transport.Run(ctx, grubCmd)
	if err != nil {
		return false, "", fmt.Errorf("check grub_parameter: transport error: %w", err)
	}
	persistentOK := strings.Contains(res.Stdout, needle) || strings.Contains(res.Stdout, needleFlag)

	if !runningOK {
		return false, fmt.Sprintf("grub_parameter: %s not set to %q in /proc/cmdline", key, expected), nil
	}
	if !persistentOK {
		return false, fmt.Sprintf("grub_parameter: %s not found in /etc/default/grub GRUB_CMDLINE_LINUX", key), nil
	}
	return true, fmt.Sprintf("grub_parameter: %s=%s (running and persistent)", key, expected), nil
}

// containsCmdlineParam checks whether a kernel cmdline string contains
// key=expected or the bare key (for boolean 0/1 parameters).
func containsCmdlineParam(cmdline, key, expected string) bool {
	for _, token := range strings.Fields(cmdline) {
		if token == key+"="+expected {
			return true
		}
		// Boolean flag with no value (e.g. "quiet").
		if expected == "1" && token == key {
			return true
		}
	}
	return false
}

// checkSelinuxState checks the current SELinux enforcement state.
// Params: state ("Enforcing", "Permissive", or "Disabled").
func checkSelinuxState(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	want, err := stringParam(params, "state")
	if err != nil {
		return false, "", err
	}
	res, err := transport.Run(ctx, "getenforce 2>/dev/null")
	if err != nil {
		return false, "", fmt.Errorf("check selinux_state: transport error: %w", err)
	}
	got := strings.TrimSpace(res.Stdout)
	if !strings.EqualFold(got, want) {
		return false, fmt.Sprintf("selinux_state: got %q, expected %q", got, want), nil
	}
	return true, fmt.Sprintf("selinux_state: %s", got), nil
}

// checkSystemdTarget checks the default systemd target. Params:
// expected (exact target name, e.g. "multi-user.target") or
// not_expected (target that must NOT be the default).
func checkSystemdTarget(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	res, err := transport.Run(ctx, "systemctl get-default 2>/dev/null")
	if err != nil {
		return false, "", fmt.Errorf("check systemd_target: transport error: %w", err)
	}
	got := strings.TrimSpace(res.Stdout)

	if expected, ok := params["expected"]; ok {
		want, _ := expected.(string)
		if !strings.EqualFold(got, want) {
			return false, fmt.Sprintf("systemd_target: default is %q, expected %q", got, want), nil
		}
		return true, fmt.Sprintf("systemd_target: default is %q", got), nil
	}

	if notExpected, ok := params["not_expected"]; ok {
		bad, _ := notExpected.(string)
		if strings.EqualFold(got, bad) {
			return false, fmt.Sprintf("systemd_target: default is %q (must not be %q)", got, bad), nil
		}
		return true, fmt.Sprintf("systemd_target: default is %q (not %q)", got, bad), nil
	}

	return false, "", fmt.Errorf("check systemd_target: must specify 'expected' or 'not_expected' param")
}

// stringSliceParam extracts a required []string parameter from params.
// The YAML parser delivers this as []interface{} of strings.
func stringSliceParam(params api.Params, key string) ([]string, error) {
	v, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("check: missing required param %q", key)
	}
	switch val := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, item := range val {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("check: param %q elements must be strings, got %T", key, item)
			}
			out = append(out, s)
		}
		return out, nil
	case []string:
		return val, nil
	default:
		return nil, fmt.Errorf("check: param %q must be a list of strings, got %T", key, v)
	}
}

// shellQuote wraps s in single quotes for safe inclusion in a shell
// command string, escaping any embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
