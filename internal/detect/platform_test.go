package detect

import (
	"testing"

	"github.com/Hanalyx/kensa/api"
)

func TestOSInfo_MajorVersion(t *testing.T) {
	cases := []struct {
		version string
		want    int
	}{
		{"9.6", 9},
		{"8.10", 8},
		{"22.04", 22},
		{"8", 8},
		{"", 0},
		{"rolling", 0},
	}
	for _, c := range cases {
		if got := (OSInfo{Version: c.version}).MajorVersion(); got != c.want {
			t.Errorf("MajorVersion(%q) = %d, want %d", c.version, got, c.want)
		}
	}
}

func TestAppliesTo(t *testing.T) {
	rhel := func(min, max int) []api.Platform {
		return []api.Platform{{Family: "rhel", MinVersion: min, MaxVersion: max}}
	}
	cases := []struct {
		name      string
		platforms []api.Platform
		os        OSInfo
		want      bool
	}{
		{"no constraint applies anywhere", nil, OSInfo{Family: "rhel", Version: "8.10"}, true},
		{"undetectable host is never gated", rhel(9, 0), OSInfo{}, true},
		{"rhel>=9 on rhel8 -> no", rhel(9, 0), OSInfo{Family: "rhel", Version: "8.10"}, false},
		{"rhel>=9 on rhel9 -> yes", rhel(9, 0), OSInfo{Family: "rhel", Version: "9.6"}, true},
		{"rhel<=8 on rhel9 -> no", rhel(0, 8), OSInfo{Family: "rhel", Version: "9.6"}, false},
		{"rhel<=8 on rhel8 -> yes", rhel(0, 8), OSInfo{Family: "rhel", Version: "8.10"}, true},
		{"rhel 8-9 on rhel9 -> yes", rhel(8, 9), OSInfo{Family: "rhel", Version: "9.6"}, true},
		{"rhel rule on ubuntu -> no", rhel(8, 0), OSInfo{Family: "ubuntu", Version: "22.04"}, false},
		{"redhat alias matches rhel host", []api.Platform{{Family: "redhat", MinVersion: 8}}, OSInfo{Family: "rhel", Version: "9.6"}, true},
		{"derivatives: rhel rule on rocky -> yes", []api.Platform{{Family: "rhel", MinVersion: 8, Derivatives: true}}, OSInfo{Family: "rocky", Version: "9.3"}, true},
		{"no-derivatives: rhel rule on rocky -> no", []api.Platform{{Family: "rhel", MinVersion: 8}}, OSInfo{Family: "rocky", Version: "9.3"}, false},
		{"known family, unknown version -> family match suffices", rhel(9, 0), OSInfo{Family: "rhel", Version: ""}, true},
	}
	for _, c := range cases {
		if got := AppliesTo(c.platforms, c.os); got != c.want {
			t.Errorf("%s: AppliesTo = %v, want %v", c.name, got, c.want)
		}
	}
}
