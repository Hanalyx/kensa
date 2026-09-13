package supplychain

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// actions/checkout leaves its token in the working copy unless told not to,
// where every later step in the job can read it. These tests hold both halves
// of the fix: that every checkout declares persist-credentials: false with the
// assertion right behind it, and that the assertion actually detects a
// credential supplied the way checkout supplies one.
//
// The second half matters more than it looks. checkout writes the header into
// a separate config and includes it with includeIf.gitdir, so an assertion
// scoped to `git config --local` sees nothing either way and passes for the
// wrong reason. The runtime cases below reproduce that mechanism exactly.

const (
	assertScript      = "scripts/assert-no-git-credentials.sh"
	assertStepName    = "Assert no Git credential persisted"
	wantCheckouts     = 17
	wantFetchDepthSet = 4
)

type wfStep struct {
	Name string         `yaml:"name"`
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
}

type wfDoc struct {
	Jobs map[string]struct {
		Steps []wfStep `yaml:"steps"`
	} `yaml:"jobs"`
}

func workflowPaths(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := filepath.Ext(e.Name()); ext == ".yml" || ext == ".yaml" {
			out = append(out, filepath.Join(".github", "workflows", e.Name()))
		}
	}
	if len(out) == 0 {
		t.Fatal("no workflow files found")
	}
	return out
}

// TestCheckoutCredentials_Declared covers the declaration half: every checkout
// in every workflow, the assertion immediately behind it, and no other input
// disturbed.
//
// @spec system-checkout-credential-non-persistence
// @ac AC-01
func TestCheckoutCredentials_Declared(t *testing.T) {
	t.Log("// @spec system-checkout-credential-non-persistence")
	t.Log("// @ac AC-01")

	checkouts, assertions, fetchDepthZero := 0, 0, 0

	for _, wf := range workflowPaths(t) {
		var doc wfDoc
		if err := yaml.Unmarshal([]byte(readRepoFile(t, wf)), &doc); err != nil {
			t.Fatalf("parsing %s: %v", wf, err)
		}
		for jobName, job := range doc.Jobs {
			for i, st := range job.Steps {
				if !strings.Contains(st.Uses, "actions/checkout@") {
					continue
				}
				checkouts++
				where := fmt.Sprintf("%s %s step %d", wf, jobName, i)

				// C-01: the flag, and exactly false.
				got, ok := st.With["persist-credentials"]
				if !ok {
					t.Errorf("%s: checkout does not set persist-credentials", where)
				} else if got != false {
					t.Errorf("%s: persist-credentials is %v, want false", where, got)
				}

				// C-05: the pin is untouched and no unexpected input appeared.
				if !strings.Contains(st.Uses, "@") || len(strings.Split(st.Uses, "@")[1]) < 40 {
					t.Errorf("%s: checkout is not pinned to a full SHA: %q", where, st.Uses)
				}
				for k := range st.With {
					switch k {
					case "persist-credentials":
					case "fetch-depth":
						if st.With[k] == 0 {
							fetchDepthZero++
						}
					default:
						t.Errorf("%s: unexpected checkout input %q", where, k)
					}
				}

				// C-04: the assertion is the very next step.
				if i+1 >= len(job.Steps) {
					t.Errorf("%s: checkout is the last step; the assertion is missing", where)
					continue
				}
				next := job.Steps[i+1]
				if next.Name != assertStepName {
					t.Errorf("%s: next step is %q, want %q", where, next.Name, assertStepName)
					continue
				}
				if !strings.Contains(next.Run, assertScript) {
					t.Errorf("%s: assertion step does not run %s", where, assertScript)
					continue
				}
				assertions++
			}
		}
	}

	if checkouts != wantCheckouts {
		t.Errorf("found %d checkout steps, spec approves %d", checkouts, wantCheckouts)
	}
	if assertions != wantCheckouts {
		t.Errorf("found %d immediately-following assertions, want %d", assertions, wantCheckouts)
	}
	if fetchDepthZero != wantFetchDepthSet {
		t.Errorf("found %d fetch-depth: 0 inputs, want %d preserved", fetchDepthZero, wantFetchDepthSet)
	}
}

// TestCheckoutCredentials_ScriptIsNotVacuous requires the assertion to read the
// effective configuration. An assertion scoped to --local cannot see a
// credential supplied through includeIf, which is how checkout supplies one.
//
// @spec system-checkout-credential-non-persistence
// @ac AC-01
func TestCheckoutCredentials_ScriptIsNotVacuous(t *testing.T) {
	t.Log("// @spec system-checkout-credential-non-persistence")
	t.Log("// @ac AC-01")

	body := readRepoFile(t, assertScript)
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "extraheader") && strings.Contains(trimmed, "--local") {
			t.Errorf("the extraheader lookup is scoped to --local, which cannot see an includeIf credential: %s", trimmed)
		}
	}
	// C-02: values are read by name only.
	if !strings.Contains(body, "--name-only") {
		t.Error("the script does not read configuration with --name-only")
	}
}

func requireGit(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("assertion script is a Linux CI script; GOOS=%s", runtime.GOOS)
	}
	for _, bin := range []string{"bash", "git"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("required tool %q not found: %v", bin, err)
		}
	}
}

func runAssert(t *testing.T, repo string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", filepath.Join(repoRoot(t), assertScript), repo)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("running the assertion: %v", err)
		}
		code = ee.ExitCode()
	}
	return code, string(out)
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

// TestCheckoutCredentials_RuntimeFakeMarker drives the real script against a
// credential supplied exactly as checkout supplies one, and requires the marker
// never to reach the output.
//
// @spec system-checkout-credential-non-persistence
// @ac AC-01
func TestCheckoutCredentials_RuntimeFakeMarker(t *testing.T) {
	t.Log("// @spec system-checkout-credential-non-persistence")
	t.Log("// @ac AC-01")
	requireGit(t)

	const marker = "FAKE_MARKER_MUST_NOT_APPEAR_7b21" // pragma: allowlist secret

	newRepo := func(t *testing.T) string {
		dir := t.TempDir()
		repo := filepath.Join(dir, "repo")
		if err := os.MkdirAll(repo, 0o755); err != nil {
			t.Fatal(err)
		}
		gitIn(t, repo, "init", "-q")
		return repo
	}

	t.Run("absent", func(t *testing.T) {
		repo := newRepo(t)
		code, out := runAssert(t, repo)
		if code != 0 {
			t.Errorf("exit=%d on a clean repository, want 0\n%s", code, out)
		}
		if strings.Contains(out, marker) {
			t.Error("marker appeared in output")
		}
	})

	t.Run("present via includeIf", func(t *testing.T) {
		repo := newRepo(t)
		cred := filepath.Join(filepath.Dir(repo), "git-credentials-fake.config")
		gitIn(t, repo, "config", "--file", cred, "http.https://github.com/.extraheader", "AUTHORIZATION: basic "+marker)
		gitIn(t, repo, "config", "--local", "includeIf.gitdir:"+repo+"/.git.path", cred)

		code, out := runAssert(t, repo)
		if code != 1 {
			t.Errorf("exit=%d with a persisted credential, want 1\n%s", code, out)
		}
		if strings.Contains(out, marker) {
			t.Errorf("the assertion printed the credential value:\n%s", out)
		}
	})

	t.Run("include left behind without the header", func(t *testing.T) {
		repo := newRepo(t)
		cred := filepath.Join(filepath.Dir(repo), "git-credentials-fake.config")
		gitIn(t, repo, "config", "--file", cred, "http.https://github.com/.extraheader", "AUTHORIZATION: basic "+marker)
		gitIn(t, repo, "config", "--local", "includeIf.gitdir:"+repo+"/.git.path", cred)
		gitIn(t, repo, "config", "--file", cred, "--unset-all", "http.https://github.com/.extraheader")

		code, out := runAssert(t, repo)
		if code != 1 {
			t.Errorf("exit=%d with the include still in place, want 1\n%s", code, out)
		}
		if strings.Contains(out, marker) {
			t.Error("marker appeared in output")
		}
	})
}
