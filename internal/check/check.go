// Package check dispatches read-only checks against a remote host to
// determine whether a rule's desired state is already satisfied.
// Each check method maps to one [api.Check.Method] string; multi-check
// composition uses AND semantics via the [api.Check.Checks] slice.
package check

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
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
	case "set_compare":
		return checkSetCompare(ctx, transport, chk.Params)
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
// selectMatchLine returns one line from grep stdout: the last non-empty line
// when last is true (drop-in override precedence — later files win), else the
// first. Returns "" when there is no match.
func selectMatchLine(stdout string, last bool) string {
	var chosen string
	for _, ln := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		if !last {
			return ln
		}
		chosen = ln
	}
	return chosen
}

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
	// dropin_dir reads the base file AND a *.conf.d/ drop-in directory together,
	// with the LAST match winning (the conventional drop-in override precedence,
	// e.g. /etc/security/pwquality.conf + pwquality.conf.d/). Without it a value
	// set only in a drop-in — the location CIS/STIG remediation writes to — is
	// missed and the host is FALSE-FAILED.
	dropinDir := optionalStringParam(params, "dropin_dir", "")

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
	tolerateExit := false
	lastWins := false
	switch {
	case dropinDir != "":
		// Read the base file AND its drop-in directory. An unmatched glob (empty
		// or absent dir) makes grep exit non-zero even when the base file
		// matched, so select by stdout content, not exit code.
		cmd = fmt.Sprintf("grep -E %s %s %s/*.conf 2>/dev/null", shellQuote(pattern), shellQuote(path), shellQuote(dropinDir))
		tolerateExit = true
		lastWins = true
	case scanPattern != "":
		// Directory scan: grep recursively using the scan pattern as a file glob suffix.
		cmd = fmt.Sprintf("grep -rE %s %s/*.%s 2>/dev/null", shellQuote(pattern), shellQuote(path), shellQuote(scanPattern))
	default:
		cmd = fmt.Sprintf("grep -E %s %s 2>/dev/null", shellQuote(pattern), shellQuote(path))
	}

	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check config_value: transport error: %w", err)
	}
	if !tolerateExit && res.ExitCode != 0 {
		return false, fmt.Sprintf("config_value: key %q not found in %s", key, path), nil
	}

	// Select the effective matching line: last-wins under drop-in precedence,
	// otherwise the first match.
	line := selectMatchLine(res.Stdout, lastWins)
	if line == "" {
		return false, fmt.Sprintf("config_value: key %q not found in %s", key, path), nil
	}
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

	// A rule may nominate one exit code meaning "I cannot reach a verdict",
	// normally because the operator has not supplied something only they can.
	// Opt-in: without the param, every exit code keeps its current meaning.
	//
	// This exists so a command check can say what set_compare already could.
	// Before it, the only ways out of a command check were pass, fail and
	// broken, so a rule needing an operator-declared value had to pick one of
	// three wrong answers. A policy threshold Kensa has no basis to choose is
	// the case: shipping a default would decide it for the site, and failing
	// would call an unconfigured host non-compliant.
	notAssessableExit, hasNA := intParam(params, "not_assessable_exit")

	res, err := transport.Run(ctx, rawCmd)
	if err != nil {
		return false, "", fmt.Errorf("check command: transport error: %w", err)
	}
	// Checked before the pass/fail comparison, because "I cannot tell" is not a
	// verdict this code should then go on to interpret.
	if hasNA && res.ExitCode == notAssessableExit {
		detail := strings.TrimSpace(res.Stdout)
		if detail == "" {
			detail = "the check reported it cannot assess this host"
		}
		return false, "", fmt.Errorf("%w: %s", ErrNotAssessable, detail)
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
// effective kernel ruleset loaded by auditd, read with auditctl -l.
//
// A line passes when some loaded rule covers it (auditRuleCovers): the same
// action and list, the same filters once names and aliases are resolved on
// the target, the same path or dir field and perm, and for an always rule a
// syscall mask that contains the requirement's. A loaded rule over more
// syscalls records every event the requirement asks for, so it passes; it
// is not a duplicate of the requirement, which is a separate question the
// audit_rule_set guard asks (AuditRuleIdentity). The key label does not
// decide compliance: a host that audits writes to /etc/passwd under another
// key is compliant, and a rule that needs its own key says so with
// key_required.
//
// When the listing cannot show whether a line is covered, the check reports
// ErrNotAssessable rather than pass or fail, which a scan reports as
// skipped. The main case is an arch-less watch: auditctl -l prints a path=
// rule and a dir= rule on the same file or directory both as -w, and they
// record different events. Over a transport with audit netlink (the agent),
// the check reads the kernel rule itself, whose field type settles it.
//
// Open limit: rule order is not modeled. A never rule loaded ahead of a
// covering always rule suppresses that rule's records, and the check does
// not detect it.
//
// Params: rule (full audit rule string, one or more lines); key_required
// (optional bool, default false: when true, every line must also be loaded
// under its own -k key).
func checkAuditRuleExists(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	rule, err := stringParam(params, "rule")
	if err != nil {
		return false, "", err
	}
	keyRequired := false
	if v, ok := params["key_required"]; ok {
		b, isBool := v.(bool)
		if !isBool {
			return false, "", fmt.Errorf("check audit_rule_exists: key_required must be a boolean, got %T", v)
		}
		keyRequired = b
	}

	res, err := transport.Run(ctx, "auditctl -l")
	if err != nil {
		return false, "", fmt.Errorf("check audit_rule_exists: transport error: %w", err)
	}
	// A non-zero exit means the loaded ruleset could not be READ, which is not
	// the same as the rule being absent. Reporting "rule line not loaded" here
	// would state something the check never measured.
	//
	// The case that forced this: on RHEL 10 `auditctl` moved out of the `audit`
	// package into `audit-rules`, which a stock install does not pull in. The
	// command is then missing, stdout is empty, and every audit rule on the
	// host reported non-compliant for a reason that had nothing to do with its
	// audit configuration. `rpm -q audit` still says the package is present,
	// so the cause is not obvious from the host either.
	if !res.OK() {
		detail := strings.TrimSpace(res.Stderr)
		if detail == "" {
			detail = fmt.Sprintf("auditctl -l exited %d with no message", res.ExitCode)
		}
		return false, "", fmt.Errorf(
			"%w: cannot read the loaded audit ruleset (%s); on RHEL 10 auditctl "+
				"ships in the 'audit-rules' package, which a stock install omits",
			ErrNotAssessable, detail)
	}
	loaded := strings.Split(res.Stdout, "\n")

	// A rule may carry several lines — e.g. a syscall control's b32 + b64
	// variants, or EPERM + EACCES pairs. Every line must be present.
	var reqs []string
	for _, line := range strings.Split(rule, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			reqs = append(reqs, line)
		}
	}
	target, err := ReadAuditTarget(ctx, transport, append(append([]string{}, reqs...), loaded...))
	if err != nil {
		return false, "", fmt.Errorf("check audit_rule_exists: read the host facts audit rules depend on: %w", err)
	}

	var otherKey, unsure []string
	var netlink []string
	netlinkRead := false
	for _, line := range reqs {
		v, got, why := auditLineCoverage(line, loaded, target, keyRequired)
		if v == auditLineAmbiguous {
			if !netlinkRead {
				netlink, netlinkRead = auditNetlinkListing(transport), true
			}
			if netlink != nil {
				v, got, why = auditLineCoverage(line, netlink, target, keyRequired)
			}
		}
		switch v {
		case auditLineOwnKey:
		case auditLineOtherKey:
			otherKey = append(otherKey, got)
		case auditLineAmbiguous:
			unsure = append(unsure, fmt.Sprintf("%s (%s)", normaliseAuditRule(line), why))
		default:
			if keyRequired {
				return false, fmt.Sprintf("audit_rule_exists: rule line not loaded under its own key (key_required): %s", normaliseAuditRule(line)), nil
			}
			return false, fmt.Sprintf("audit_rule_exists: rule line not loaded: %s%s", normaliseAuditRule(line),
				auditPermClassDetail(line, loaded)), nil
		}
	}
	if len(unsure) > 0 {
		return false, "", fmt.Errorf("%w: audit_rule_exists: the loaded ruleset cannot show whether %d line(s) "+
			"are covered: %s.%s", ErrNotAssessable, len(unsure), strings.Join(unsure, "; "), auditWatchKindNote(unsure))
	}
	if len(otherKey) > 0 {
		return true, fmt.Sprintf("audit_rule_exists: all rule actions present in loaded ruleset; %d line(s) audited under another key: %s",
			len(otherKey), strings.Join(otherKey, "; ")), nil
	}
	return true, "audit_rule_exists: all rule lines present in loaded ruleset", nil
}

// auditWatchKindNote explains the watch case in plain terms, because the
// skipped verdict it produces is not one only the operator can resolve.
func auditWatchKindNote(unsure []string) string {
	for _, u := range unsure {
		if strings.Contains(u, auditWatchKindUnknown) {
			return " auditctl -l prints a path= watch and a dir= rule on the same file or directory the same way " +
				"(-w), so this listing cannot tell them apart, and they record different events: a dir= rule on " +
				"a directory covers its whole subtree, and a dir= rule on a file stops recording once the file " +
				"is replaced by rename. Over this transport the kernel rule cannot be read; the agent transport " +
				"reads it through audit netlink and resolves it."
		}
	}
	return ""
}

type auditLineVerdict int

const (
	auditLineMissing auditLineVerdict = iota
	auditLineOwnKey
	auditLineOtherKey
	auditLineAmbiguous
)

// auditLineCoverage finds the best loaded line for one requirement line:
// covered under its own key, then covered under another key (unless
// keyRequired), then a line that may cover it, then none.
func auditLineCoverage(line string, loaded []string, t *AuditTarget, keyRequired bool) (auditLineVerdict, string, string) {
	req := parseAuditK(line, auditSource)
	if !req.ok {
		return auditLineMissing, "", "not an audit rule"
	}
	other, why := "", ""
	ambiguous := false
	for _, l := range loaded {
		got := parseAuditK(l, auditLoaded)
		if !got.ok {
			continue
		}
		c, w := auditRuleCovers(req, got, t)
		ownKey := auditKeysCover(req.keys, got.keys)
		switch {
		case c == AuditCovered && ownKey:
			return auditLineOwnKey, strings.TrimSpace(l), ""
		case c == AuditCovered && !keyRequired && other == "":
			other = strings.TrimSpace(l)
		case c == AuditCoverAmbiguous && (ownKey || !keyRequired) && !ambiguous:
			ambiguous, why = true, w
		}
	}
	switch {
	case other != "":
		return auditLineOtherKey, other, ""
	case ambiguous:
		return auditLineAmbiguous, "", why
	}
	return auditLineMissing, "", ""
}

// auditKeysCover reports whether got carries every key want names. A rule
// with no key is covered under any key.
func auditKeysCover(want, got []string) bool {
	have := map[string]bool{}
	for _, k := range got {
		have[k] = true
	}
	for _, k := range want {
		if !have[k] {
			return false
		}
	}
	return true
}

// auditNetlinkCommand labels the netlink read in check evidence. It is not a
// shell command; it names the kernel request the agent made.
const auditNetlinkCommand = "audit netlink AUDIT_LIST_RULES (agent transport)"

// auditNetlinkListing reads the loaded rules through audit netlink when the
// transport offers it, rendered so a watch keeps its path or dir field type.
// Nil when it is not offered or cannot be read; the caller then keeps the
// auditctl -l answer. Run wraps every transport in a recorder, so the
// recorder is looked through, and the read is recorded as evidence like a
// command.
func auditNetlinkListing(transport api.Transport) []string {
	inner := transport
	rec, _ := transport.(*recordingTransport)
	if rec != nil {
		inner = rec.inner
	}
	at, ok := inner.(interface {
		AuditClient() (auditnl.AuditClient, error)
	})
	if !ok {
		return nil
	}
	c, err := at.AuditClient()
	if err != nil {
		return nil
	}
	defer c.Close()
	lines, err := auditnl.RulesText(c)
	if rec != nil {
		r := commandRecord{command: auditNetlinkCommand}
		if err != nil {
			r.stderr, r.exitCode = err.Error(), 1
		} else {
			r.stdout, r.truncated = capEvidenceField(strings.Join(lines, "\n"))
		}
		rec.cmds = append(rec.cmds, r)
	}
	if err != nil {
		return nil
	}
	return lines
}

// AuditLineLoaded reports whether a single audit rule line is loaded under
// its own key: some line of loaded (auditctl -l output) has the canonical
// form parseAuditRule gives the rule, or holds a whole captured class list
// for it (sameAuditRule), and carries every -k key the rule names. A rule
// with no key matches under any key.
//
// It is the earlier matcher, kept only for the audit_rule_set shell
// staged-rollback verdict (through AuditLineMaybeLoaded). audit_rule_exists
// uses auditRuleCovers and the duplicate guard uses AuditRuleIdentity.
func AuditLineLoaded(rule string, loaded []string) bool {
	want := parseAuditRule(rule)
	if want.rule == "" {
		return false
	}
	for _, l := range loaded {
		got := parseAuditRule(l)
		if !sameAuditRule(want, got) {
			continue
		}
		keyed := true
		for k := range want.keys {
			if !got.keys[k] {
				keyed = false
				break
			}
		}
		if keyed {
			return true
		}
	}
	return false
}

// auditPermClassDetail explains a perm-class rule's miss: for the loaded line
// with the same arch and filters whose syscalls come closest to a captured
// list, the syscalls it lacks. Empty when the rule is not a perm-class rule or
// no loaded line has the same arch and filters.
func auditPermClassDetail(rule string, loaded []string) string {
	want := parseAuditRule(rule)
	if want.permRest == "" || !want.noSyscalls {
		return ""
	}
	var best []string
	bestLine := ""
	for _, l := range loaded {
		got := parseAuditRule(l)
		if got.permRest != want.permRest || got.syscalls["all"] {
			continue
		}
		miss := auditPermClassMissing(want.arch, want.perm, got.syscalls)
		if bestLine == "" || len(miss) < len(best) {
			best, bestLine = miss, strings.TrimSpace(l)
		}
	}
	switch {
	case bestLine == "":
		return ""
	case len(best) == 0:
		return fmt.Sprintf(" (no captured syscall list for arch %s perm %s; closest loaded line: %s)",
			want.arch, want.perm, bestLine)
	default:
		return fmt.Sprintf(" (closest loaded line lacks syscalls %s: %s)", strings.Join(best, ","), bestLine)
	}
}

// sameAuditRule reports whether got is the loaded form of want, by the
// equivalences parseAuditRule applies. Equal canonical forms match; that
// covers the netlink listing, whose "-S all" is the canonical form of a rule
// with no -S. Otherwise only a perm-class rule written with no -S at all can
// match, and only a loaded line with the same arch and filters whose syscalls
// contain one whole auditPermClass list: the list auditctl, and so augenrules,
// loads that rule with. A rule that says "-S all" keeps exact matching,
// because the kernel's perm classes hold syscalls the auditctl list lacks
// (for example chown32 and truncate64 for b32), so the expanded line audits
// less than it.
func sameAuditRule(want, got auditRuleForm) bool {
	if want.rule == got.rule {
		return true
	}
	if want.permRest == "" || want.permRest != got.permRest || !want.noSyscalls {
		return false
	}
	return auditPermClassMissing(want.arch, want.perm, got.syscalls) == nil
}

// auditPermClassMissing returns nil when syscalls contains one whole captured
// list for arch and perm, and otherwise the syscalls missing from the closest
// list. A pair with no captured list returns a non-nil empty result: there is
// nothing to compare against, so it never matches.
func auditPermClassMissing(arch, perm string, syscalls map[string]bool) []string {
	lists := auditPermClass[arch][perm]
	if len(lists) == 0 {
		return []string{}
	}
	var best []string
	for _, list := range lists {
		var miss []string
		for _, sc := range list {
			if !syscalls[sc] {
				miss = append(miss, sc)
			}
		}
		if len(miss) == 0 {
			return nil
		}
		if best == nil || len(miss) < len(best) {
			best = miss
		}
	}
	return best
}

// auditRuleForm is one audit rule line reduced to the kernel rule it loads.
// rule is the canonical form without the key, or "" when the line is not a
// watch (-w) or a syscall rule (-a/-A); keys holds the -k and -F key= labels.
type auditRuleForm struct {
	rule string
	keys map[string]bool
	// For a syscall rule with an arch=, a path= or dir= filter and a perm
	// filter: permRest is the canonical form without its syscalls, arch and
	// perm name the auditPermClass entry, and syscalls is the syscall set.
	// noSyscalls says the line named no -S at all, so auditctl loads it with
	// the auditPermClass list. Empty otherwise.
	permRest   string
	arch, perm string
	syscalls   map[string]bool
	noSyscalls bool
}

// parseAuditRule reduces an audit rule line to its canonical form: "-k k"
// and "-F key=k" are the key; auid!=unset, auid!=-1 and auid!=4294967295 are
// one value; a -C comparison's sides are ordered; "exit,always" and
// "always,exit" are one action and list, and -A is read as -a; syscall lists
// and permission letters are sets; an exit rule with no -S is "-S all"; and
// a path= or dir= rule with no arch, no syscalls and only a perm filter is
// the watch it loads as.
func parseAuditRule(line string) auditRuleForm {
	form := auditRuleForm{keys: map[string]bool{}}
	fields := splitAuditFlags(strings.Fields(line))
	var (
		isWatch, isSyscall     bool
		watchPath, watchPerm   string
		action, list           string
		syscalls               = map[string]bool{}
		filters                = map[string]bool{}
		pathTok, permTok, arch string
		dirTok                 string
		namedSyscalls          bool
	)
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		next := ""
		if i+1 < len(fields) {
			next = fields[i+1]
		}
		switch f {
		case "-w":
			isWatch, watchPath = true, canonAuditPath(next)
			i++
		case "-p":
			watchPerm = canonAuditPerm(next)
			i++
		case "-a", "-A":
			isSyscall = true
			for _, part := range strings.Split(next, ",") {
				switch part {
				case "always", "never":
					action = part
				default:
					list = part
				}
			}
			i++
		case "-S":
			namedSyscalls = true
			for _, sc := range strings.Split(next, ",") {
				if sc != "" {
					syscalls[sc] = true
				}
			}
			i++
		case "-F":
			i++
			if strings.HasPrefix(next, "key=") {
				form.keys[strings.TrimPrefix(next, "key=")] = true
				continue
			}
			name, tok := canonAuditFilter(next)
			switch name {
			case "path":
				pathTok = tok
			case "dir":
				dirTok = tok
			case "perm":
				permTok = tok
			case "arch":
				arch = tok
			}
			filters[tok] = true
		case "-C":
			filters["-C "+canonAuditCompare(next)] = true
			i++
		case "-k":
			form.keys[next] = true
			i++
		}
	}

	if isSyscall && list == "exit" && (len(syscalls) == 0 || syscalls["all"]) {
		syscalls = map[string]bool{"all": true}
		// A path= or dir= rule over every syscall with only a perm filter is
		// the kernel rule -w loads on a file or a directory, and auditctl -l
		// prints it as -w. The kernel answers "Rule exists" for -w and the
		// path= rule on one file, and for -w and the dir= rule on one
		// directory, so each pair is one kernel rule (C-03).
		target := pathTok
		if target == "" {
			target = dirTok
		}
		if action == "always" && arch == "" && target != "" && (pathTok == "" || dirTok == "") &&
			permTok != "" && len(filters) == 2 {
			isSyscall, isWatch = false, true
			watchPath = target[strings.IndexByte(target, '=')+1:]
			watchPerm = permTok[strings.IndexByte(permTok, '=')+1:]
			filters = map[string]bool{}
		}
	}

	switch {
	case isWatch && watchPath != "":
		if watchPerm == "" {
			watchPerm = "rwxa"
		}
		form.rule = "-w " + watchPath + " -p " + watchPerm
		if len(filters) > 0 {
			form.rule += " " + strings.Join(sortedKeys(filters), " ")
		}
	case isSyscall:
		rest := "-a " + action + "," + list
		if len(filters) > 0 {
			rest += " " + strings.Join(sortedKeys(filters), " ")
		}
		form.rule = "-a " + action + "," + list + " -S " + strings.Join(sortedKeys(syscalls), ",")
		if len(filters) > 0 {
			form.rule += " " + strings.Join(sortedKeys(filters), " ")
		}
		// Only an equality arch filter names the arch whose syscalls the
		// list holds; arch!=b64 covers the other arch.
		if list == "exit" && strings.HasPrefix(arch, "-F arch=") && (pathTok != "" || dirTok != "") &&
			permTok != "" {
			form.permRest = rest
			form.arch = strings.TrimPrefix(arch, "-F arch=")
			form.perm = permTok[strings.IndexByte(permTok, '=')+1:]
			form.syscalls = syscalls
			form.noSyscalls = !namedSyscalls
		}
	}
	return form
}

// canonAuditFilter returns a -F field's name and its canonical "-F" token.
// An unset id (unset, -1 or 4294967295, which libaudit parses to one value)
// is written -1, and perm letters in rwxa order.
func canonAuditFilter(tok string) (string, string) {
	idx := strings.IndexAny(tok, "!=<>&")
	if idx <= 0 {
		return tok, "-F " + tok
	}
	name, rest := tok[:idx], tok[idx:]
	op := ""
	for _, o := range []string{"!=", ">=", "<=", "&=", "=", ">", "<", "&"} {
		if strings.HasPrefix(rest, o) {
			op = o
			break
		}
	}
	value := strings.TrimPrefix(rest, op)
	switch {
	case value == "unset" || value == "4294967295":
		value = "-1"
	case name == "perm":
		value = canonAuditPerm(value)
	case name == "path" || name == "dir":
		value = canonAuditPath(value)
	}
	return name, "-F " + name + op + value
}

// canonAuditPath drops trailing slashes from a watched path, so
// /etc/sudoers.d/ and /etc/sudoers.d compare equal. auditctl -l may print a
// watch without the slash it was written with. The root path stays "/".
func canonAuditPath(p string) string {
	if t := strings.TrimRight(p, "/"); t != "" {
		return t
	}
	return p
}

// splitAuditFlags separates a flag from an argument written against it,
// such as -Farch=b64, -Sexecve or -pwa, which auditctl's option parser
// accepts, into the two tokens the parser below expects.
func splitAuditFlags(fields []string) []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if len(f) > 2 && f[0] == '-' && strings.IndexByte("wpaASFCk", f[1]) >= 0 {
			out = append(out, f[:2], f[2:])
			continue
		}
		out = append(out, f)
	}
	return out
}

// canonAuditCompare orders the two sides of a -C comparison. libaudit parses
// "euid!=uid" and "uid!=euid" into one comparison; -C accepts only = and !=.
func canonAuditCompare(tok string) string {
	op := "!="
	idx := strings.Index(tok, op)
	if idx < 0 {
		op = "="
		idx = strings.Index(tok, op)
	}
	if idx <= 0 {
		return tok
	}
	left, right := tok[:idx], tok[idx+len(op):]
	if right < left {
		left, right = right, left
	}
	return left + op + right
}

// canonAuditPerm writes audit permission letters in rwxa order, the order
// auditctl -l prints them. A value with any other character is kept as
// written, so it never compares equal to a valid one by accident.
func canonAuditPerm(p string) string {
	if strings.Trim(p, "rwxa") != "" {
		return p
	}
	var b strings.Builder
	for _, c := range "rwxa" {
		if strings.ContainsRune(p, c) {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// sortedKeys returns a set's members in sorted order.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
		//   - a `modprobe: ... not found` error with a non-zero exit — the module
		//     is absent from the kernel tree and cannot be loaded at all, which
		//     satisfies "not available",
		//   - `insmod /lib/modules/.../<mod>.ko` lines — the module IS loadable.
		// Match in Go (not a shell `grep`) so both no-op forms and the not-found
		// case are recognized and the logic is unit-testable.
		//
		// The shell reports a missing or unrunnable modprobe as "not found" too
		// (dash: `sh: 1: modprobe: not found`, bash: `sh: line 1: modprobe:
		// command not found`), with exit 127 or 126. That says nothing about the
		// module, so it is a check error, never a verdict.
		cmd := fmt.Sprintf("modprobe -n --show-depends %s 2>&1", shellQuote(name))
		res, err := transport.Run(ctx, cmd)
		if err != nil {
			return false, "", fmt.Errorf("check kernel_module_state: transport error: %w", err)
		}
		out := res.Stdout
		if res.ExitCode == 126 || res.ExitCode == 127 {
			return false, "", fmt.Errorf("check kernel_module_state: modprobe could not run (exit %d): %s",
				res.ExitCode, strings.TrimSpace(out))
		}
		if strings.Contains(out, "install /bin/true") || strings.Contains(out, "install /bin/false") {
			return true, fmt.Sprintf("kernel_module_state: %s is disabled (install no-op) and not loaded", name), nil
		}
		if res.ExitCode != 0 && modprobeModuleNotFound(out) {
			return true, fmt.Sprintf("kernel_module_state: %s is not available (module not present) and not loaded", name), nil
		}
		return false, fmt.Sprintf("kernel_module_state: module %s is loadable (no install /bin/true|/bin/false override)", name), nil
	}
}

// modprobeModuleNotFound reports whether out holds modprobe's own
// module-not-found message, for example `modprobe: FATAL: Module atm not
// found in directory /lib/modules/<release>`. Only a line that modprobe
// itself printed counts; a shell's `modprobe: not found` starts with the
// shell's name instead.
func modprobeModuleNotFound(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "modprobe: ") && strings.Contains(line, "Module ") && strings.Contains(line, " not found") {
			return true
		}
	}
	return false
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

// intParam reads an optional integer param and reports whether it was present.
// YAML numbers decode as int or float64 depending on the decoder, so both are
// accepted rather than assuming one.
func intParam(params api.Params, key string) (int, bool) {
	v, ok := params[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}
