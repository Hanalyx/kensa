// Package check dispatches read-only checks against a remote host to
// determine whether a rule's desired state is already satisfied.
// Each check method maps to one [api.Check.Method] string; multi-check
// composition uses AND semantics via the [api.Check.Checks] slice.
package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa-go/api"
)

// Run dispatches chk to the appropriate check method and returns
// (passed, detail, error). When chk.Checks is non-empty the check
// uses AND composition: all child checks must pass for the result to
// be true. Individual method dispatch errors are returned as errors;
// transport-level failures are surfaced via the error return rather
// than the bool.
func Run(ctx context.Context, transport api.Transport, chk api.Check) (bool, string, error) {
	if len(chk.Checks) > 0 {
		return runMulti(ctx, transport, chk.Checks)
	}
	switch chk.Method {
	case "config_value":
		return checkConfigValue(ctx, transport, chk.Params)
	case "sysctl_value":
		return checkSysctlValue(ctx, transport, chk.Params)
	case "package_installed":
		return checkPackageInstalled(ctx, transport, chk.Params)
	case "package_absent":
		return checkPackageAbsent(ctx, transport, chk.Params)
	case "file_exists":
		return checkFileExists(ctx, transport, chk.Params)
	case "file_absent":
		return checkFileAbsent(ctx, transport, chk.Params)
	case "file_permissions":
		return checkFilePermissions(ctx, transport, chk.Params)
	case "file_content_match":
		return checkFileContentMatch(ctx, transport, chk.Params)
	case "service_enabled":
		return checkServiceEnabled(ctx, transport, chk.Params)
	case "service_active":
		return checkServiceActive(ctx, transport, chk.Params)
	case "command":
		return checkCommand(ctx, transport, chk.Params)
	default:
		return false, "", fmt.Errorf("check: unknown method %q", chk.Method)
	}
}

// runMulti executes each child check and returns true only when every
// child passes (AND semantics). Detail combines the individual details,
// separated by semicolons.
func runMulti(ctx context.Context, transport api.Transport, checks []api.Check) (bool, string, error) {
	var details []string
	allPass := true
	for _, c := range checks {
		passed, detail, err := Run(ctx, transport, c)
		if err != nil {
			return false, "", err
		}
		if detail != "" {
			details = append(details, detail)
		}
		if !passed {
			allPass = false
		}
	}
	return allPass, strings.Join(details, "; "), nil
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
	expected, err := stringParam(params, "expected")
	if err != nil {
		return false, "", err
	}
	delimiter := optionalStringParam(params, "delimiter", "=")
	scanPattern := optionalStringParam(params, "scan_pattern", "")

	var cmd string
	if scanPattern != "" {
		// Directory scan: grep recursively using the scan pattern as a
		// file glob suffix.
		pattern := fmt.Sprintf(`^\s*%s\s*[%s:]\s*`, key, delimiter)
		cmd = fmt.Sprintf("grep -rE %s %s/*.%s 2>/dev/null", shellQuote(pattern), shellQuote(path), shellQuote(scanPattern))
	} else {
		pattern := fmt.Sprintf(`^\s*%s\s*[%s:]\s*`, key, delimiter)
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
	// Split on delimiter or colon to isolate the value.
	sep := delimiter
	if !strings.Contains(line, sep) {
		sep = ":"
	}
	parts := strings.SplitN(line, sep, 2)
	if len(parts) < 2 {
		return false, fmt.Sprintf("config_value: could not parse value from line %q", line), nil
	}
	got := strings.TrimSpace(parts[1])
	if !strings.EqualFold(got, expected) {
		return false, fmt.Sprintf("config_value: key %q: got %q, expected %q", key, got, expected), nil
	}
	return true, fmt.Sprintf("config_value: key %q = %q", key, got), nil
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
	if got != expected {
		return false, fmt.Sprintf("sysctl_value: %s = %q, expected %q", key, got, expected), nil
	}
	return true, fmt.Sprintf("sysctl_value: %s = %q", key, got), nil
}

// checkPackageInstalled checks whether an RPM package is installed.
// Params: name.
func checkPackageInstalled(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	name, err := stringParam(params, "name")
	if err != nil {
		return false, "", err
	}
	cmd := fmt.Sprintf("rpm -q %s >/dev/null 2>&1", shellQuote(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check package_installed: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("package_installed: %s is not installed", name), nil
	}
	return true, fmt.Sprintf("package_installed: %s is installed", name), nil
}

// checkPackageAbsent checks whether an RPM package is NOT installed.
// Params: name.
func checkPackageAbsent(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	name, err := stringParam(params, "name")
	if err != nil {
		return false, "", err
	}
	cmd := fmt.Sprintf("rpm -q %s >/dev/null 2>&1", shellQuote(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false, "", fmt.Errorf("check package_absent: transport error: %w", err)
	}
	if res.ExitCode == 0 {
		return false, fmt.Sprintf("package_absent: %s is installed but should be absent", name), nil
	}
	return true, fmt.Sprintf("package_absent: %s is not installed", name), nil
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
// owner and group, of a file. Params: path, mode (octal string like
// "0644"), optionally owner and group.
func checkFilePermissions(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	path, err := stringParam(params, "path")
	if err != nil {
		return false, "", err
	}
	mode, err := stringParam(params, "mode")
	if err != nil {
		return false, "", err
	}
	owner := optionalStringParam(params, "owner", "")
	group := optionalStringParam(params, "group", "")

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
	if gotModeNorm != wantMode {
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
	if !strings.Contains(out, "enabled") {
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

// checkCommand runs an arbitrary command and checks the exit code.
// Params: cmd, optionally expected_output (substring match against
// stdout).
func checkCommand(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	rawCmd, err := stringParam(params, "cmd")
	if err != nil {
		return false, "", err
	}
	expectedOutput := optionalStringParam(params, "expected_output", "")

	res, err := transport.Run(ctx, rawCmd)
	if err != nil {
		return false, "", fmt.Errorf("check command: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Sprintf("command: %q exited with code %d", rawCmd, res.ExitCode), nil
	}
	if expectedOutput != "" && !strings.Contains(res.Stdout, expectedOutput) {
		return false, fmt.Sprintf("command: output does not contain %q", expectedOutput), nil
	}
	return true, fmt.Sprintf("command: %q passed", rawCmd), nil
}

// shellQuote wraps s in single quotes for safe inclusion in a shell
// command string, escaping any embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
