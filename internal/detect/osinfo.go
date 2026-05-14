package detect

import (
	"bufio"
	"context"
	"strings"

	"github.com/Hanalyx/kensa/api"
)

// OSInfo carries the structured /etc/os-release fields the operator-
// facing UX cares about. Populated by DetectOS via a single
// `cat /etc/os-release` over the transport. Unparseable or missing
// hosts return a zero OSInfo (Family="", Version=""); callers
// should treat that as "unknown" rather than erroring — operator
// UX falls back to displaying just the hostname.
type OSInfo struct {
	// Family is the lowercase ID (e.g., "rhel", "ubuntu", "debian",
	// "fedora"). Matches /etc/os-release's ID= field.
	Family string

	// Version is the VERSION_ID field (e.g., "9.6", "22.04").
	// Empty when the host doesn't expose VERSION_ID.
	Version string

	// PrettyName is the PRETTY_NAME field (e.g., "Red Hat
	// Enterprise Linux 9.6 (Plow)") for verbose displays.
	PrettyName string
}

// Label returns a short operator-facing label for a banner — e.g.,
// "RHEL 9.6", "Ubuntu 22.04", "Fedora 41". Returns an empty string
// when neither Family nor Version is known (callers omit the
// "· OS" segment of the host banner in that case).
//
// The Family→short-name mapping covers the common Linux
// distributions; unknown families render the raw ID upper-cased.
func (o OSInfo) Label() string {
	if o.Family == "" && o.Version == "" {
		return ""
	}
	short := osShortName(o.Family)
	if short == "" {
		short = strings.ToUpper(o.Family)
	}
	if o.Version == "" {
		return short
	}
	if short == "" {
		return o.Version
	}
	return short + " " + o.Version
}

// osShortName maps the canonical /etc/os-release ID to the short
// name operators recognize. Empty for unknown families so callers
// can fall back to the raw ID.
func osShortName(family string) string {
	switch strings.ToLower(family) {
	case "rhel":
		return "RHEL"
	case "centos":
		return "CentOS"
	case "fedora":
		return "Fedora"
	case "rocky":
		return "Rocky"
	case "almalinux":
		return "AlmaLinux"
	case "ol", "oracle":
		return "Oracle Linux"
	case "ubuntu":
		return "Ubuntu"
	case "debian":
		return "Debian"
	case "alpine":
		return "Alpine"
	case "amzn":
		return "Amazon Linux"
	case "sles", "opensuse-leap", "opensuse-tumbleweed":
		return "SUSE"
	case "arch":
		return "Arch"
	}
	return ""
}

// DetectOS reads /etc/os-release on the remote host and parses it.
// Returns a zero OSInfo (NOT an error) when the file is missing or
// unparseable; the host banner falls back to hostID-only.
//
// Network failures surface as errors so the caller can decide
// whether to retry or fall through.
func DetectOS(ctx context.Context, transport api.Transport) (OSInfo, error) {
	res, err := transport.Run(ctx, "cat /etc/os-release 2>/dev/null")
	if err != nil {
		return OSInfo{}, err
	}
	if res.ExitCode != 0 {
		// Not an error: some minimal containers / older RHEL 6
		// hosts don't have /etc/os-release. The banner falls back.
		return OSInfo{}, nil
	}
	return parseOSRelease(res.Stdout), nil
}

// parseOSRelease parses /etc/os-release content. The format is
// shell-style key=value with values optionally quoted. Whitespace
// outside quotes is significant; we follow the systemd
// os-release(5) man-page rules loosely (no shell-escape support
// because real os-release files don't use them).
func parseOSRelease(content string) OSInfo {
	var info OSInfo
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		value := strings.TrimSpace(line[eq+1:])
		// Strip enclosing single or double quotes.
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		switch key {
		case "ID":
			info.Family = strings.ToLower(value)
		case "VERSION_ID":
			info.Version = value
		case "PRETTY_NAME":
			info.PrettyName = value
		}
	}
	return info
}
