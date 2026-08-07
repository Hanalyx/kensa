package varsub

import (
	"strings"
	"testing"
)

// The declared type comes from the embedded defaults, so the file that already
// holds the values is the only place a type is written down.
func TestBuiltInTypesAreDerivedFromTheDefaults(t *testing.T) {
	types, err := BuiltInTypes()
	if err != nil {
		t.Fatalf("BuiltInTypes: %v", err)
	}
	for name, want := range map[string]VarType{
		"pam_faillock_deny":     TypeInt,
		"pam_pwquality_dcredit": TypeInt, // negative
		"root_umask":            TypeString,
		"login_defs_umask":      TypeString,
		"rsyslog_remote_server": TypeString,
		"banner_text":           TypeString,
	} {
		if got := types[name]; got != want {
			t.Errorf("%s: type is %q, want %q", name, got, want)
		}
	}
	if _, known := types["a_name_kensa_never_heard_of"]; known {
		t.Error("an unknown name must not be typed")
	}
}

// A file tier is checked on the YAML type, because in a file the quoting is the
// author's and it carries the meaning.
func TestCheckFileValue(t *testing.T) {
	types := map[string]VarType{"n": TypeInt, "s": TypeString, "l": TypeList}
	for _, tc := range []struct {
		name string
		key  string
		raw  any
		err  string
	}{
		{name: "int into int", key: "n", raw: 5},
		{name: "negative int", key: "n", raw: -1},
		{name: "string into string", key: "s", raw: "027"},
		{name: "list into list", key: "l", raw: []any{"a", "b"}},
		{name: "untyped name is not policed", key: "unknown", raw: 1.5},

		{name: "string into int", key: "n", raw: "three", err: "expects integer"},
		{name: "the umask trap: number into string", key: "s", raw: 23, err: "Quote the value"},
		{name: "list into int", key: "n", raw: []any{"a"}, err: "got a list"},
		{name: "scalar into list", key: "l", raw: "a,b", err: "Write it as a YAML list"},
	} {
		err := CheckFileValue(tc.key, tc.raw, types)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		case tc.err != "" && err == nil:
			t.Errorf("%s: want error containing %q, got nil", tc.name, tc.err)
		case tc.err != "" && !strings.Contains(err.Error(), tc.err):
			t.Errorf("%s: want error containing %q, got %v", tc.name, tc.err, err)
		}
	}
}

// The advice for the umask trap must not tell an author to write the number
// YAML produced. A bare 027 arrives as 23, and quoting 23 would store a value
// they never meant.
func TestUmaskAdviceDoesNotSuggestTheParsedNumber(t *testing.T) {
	err := CheckFileValue("s", 23, map[string]VarType{"s": TypeString})
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "'23'") {
		t.Errorf("advice suggests quoting the parsed number, which stores the wrong value: %v", err)
	}
}

// The command line is checked by parse, because every --var value is text.
func TestCheckCLIValue(t *testing.T) {
	types := map[string]VarType{"n": TypeInt, "s": TypeString, "l": TypeList}
	for _, tc := range []struct{ name, key, raw, err string }{
		{name: "numeric override works", key: "n", raw: "5"},
		{name: "negative works", key: "n", raw: "-1"},
		{name: "any text is a string", key: "s", raw: "027"},
		{name: "comma members satisfy a list", key: "l", raw: "alice,bob"},
		{name: "unknown name is not policed", key: "unknown", raw: "anything"},

		{name: "words are not integers", key: "n", raw: "three", err: "expects an integer"},
		{name: "decimals are not integers", key: "n", raw: "3.5", err: "expects an integer"},
		{name: "a unit left on the end", key: "n", raw: "600s", err: "expects an integer"},
		{name: "padded member in a list", key: "l", raw: "alice, bob", err: "whitespace"},
	} {
		err := CheckCLIValue(tc.key, tc.raw, types)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		case tc.err != "" && err == nil:
			t.Errorf("%s: want error containing %q, got nil", tc.name, tc.err)
		case tc.err != "" && !strings.Contains(err.Error(), tc.err):
			t.Errorf("%s: want error containing %q, got %v", tc.name, tc.err, err)
		}
	}
}
