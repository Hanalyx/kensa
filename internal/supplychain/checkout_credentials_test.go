package supplychain

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
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
	assertScript   = "scripts/assert-no-git-credentials.sh"
	assertStepName = "Assert no Git credential persisted"
	pinSpecPath    = "specs/system/checkout-credential-non-persistence.spec.yaml"
)

// runIsBareInvocation matches a run: body that is exactly the assertion script,
// optionally with one argument, and nothing else. A substring match would
// accept `echo ./scripts/assert-no-git-credentials.sh` or the same command
// followed by `|| true`, both of which assert nothing.
var runIsBareInvocation = regexp.MustCompile(`^\./` + regexp.QuoteMeta(assertScript) + `( +[^\s;&|]+)?$`)

type wfStep struct {
	Name string         `yaml:"name"`
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
}

type wfDoc struct {
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Name  string   `yaml:"name"`
		Steps []wfStep `yaml:"steps"`
	} `yaml:"jobs"`
}

// approvedShape is the contract, read from the spec rather than duplicated
// here, so a count or a mapping cannot be changed in one place only.
type approvedShape struct {
	workflows      []string
	totalCheckouts int
	perWorkflow    map[string]int
	fetchDepthZero map[string][]string // workflow -> job names that must carry fetch-depth: 0
	permissions    map[string]map[string]string
	assertions     int
}

func loadApprovedShape(t *testing.T) approvedShape {
	t.Helper()
	var doc struct {
		Spec struct {
			AcceptanceCriteria []struct {
				ID     string `yaml:"id"`
				Inputs struct {
					Workflows     []string `yaml:"workflows"`
					CheckoutSteps struct {
						Total   int `yaml:"total"`
						CI      int `yaml:"ci"`
						Release int `yaml:"release"`
					} `yaml:"checkout_steps"`
					PreservedInputs struct {
						FetchDepthZeroJobs map[string][]string `yaml:"fetch_depth_zero_jobs"`
					} `yaml:"preserved_inputs"`
					WorkflowPermissions map[string]map[string]string `yaml:"workflow_permissions"`
					Assertion           struct {
						Script string `yaml:"script"`
						Count  int    `yaml:"count"`
					} `yaml:"assertion"`
				} `yaml:"inputs"`
			} `yaml:"acceptance_criteria"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, pinSpecPath)), &doc); err != nil {
		t.Fatalf("parsing %s: %v", pinSpecPath, err)
	}
	for _, ac := range doc.Spec.AcceptanceCriteria {
		if ac.ID != "AC-01" {
			continue
		}
		in := ac.Inputs
		if in.Assertion.Script != assertScript {
			t.Fatalf("spec names assertion script %q, test holds %q", in.Assertion.Script, assertScript)
		}
		return approvedShape{
			workflows:      in.Workflows,
			totalCheckouts: in.CheckoutSteps.Total,
			perWorkflow: map[string]int{
				".github/workflows/ci.yml":      in.CheckoutSteps.CI,
				".github/workflows/release.yml": in.CheckoutSteps.Release,
			},
			fetchDepthZero: in.PreservedInputs.FetchDepthZeroJobs,
			permissions:    in.WorkflowPermissions,
			assertions:     in.Assertion.Count,
		}
	}
	t.Fatal("spec declares no AC-01")
	return approvedShape{}
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

// TestCheckoutCredentials_Declared covers the declaration half, bound to the
// approved spec: the flag on every checkout, a real invocation of the assertion
// immediately behind it, fetch-depth: 0 on the named jobs rather than a bare
// total, and the permissions each workflow is approved to hold.
//
// @spec system-checkout-credential-non-persistence
// @ac AC-01
func TestCheckoutCredentials_Declared(t *testing.T) {
	t.Log("// @spec system-checkout-credential-non-persistence")
	t.Log("// @ac AC-01")

	want := loadApprovedShape(t)
	found := workflowPaths(t)

	// Every approved workflow exists, and no workflow exists that the spec
	// does not name: a new one would otherwise carry unchecked checkouts.
	sort.Strings(found)
	approved := append([]string(nil), want.workflows...)
	sort.Strings(approved)
	if !reflect.DeepEqual(found, approved) {
		t.Fatalf("workflow set is %v, spec approves %v", found, approved)
	}

	checkouts, assertions := 0, 0
	perWorkflow := map[string]int{}
	sawFetchDepthZero := map[string][]string{}

	for _, wf := range found {
		var doc wfDoc
		if err := yaml.Unmarshal([]byte(readRepoFile(t, wf)), &doc); err != nil {
			t.Fatalf("parsing %s: %v", wf, err)
		}

		// C-05, enforced rather than asserted in prose: the workflow holds the
		// permissions the contract approves.
		if wantPerms, ok := want.permissions[wf]; ok {
			if !reflect.DeepEqual(doc.Permissions, wantPerms) {
				t.Errorf("%s: permissions are %v, spec approves %v", wf, doc.Permissions, wantPerms)
			}
		}

		for jobName, job := range doc.Jobs {
			for i, st := range job.Steps {
				if !strings.Contains(st.Uses, "actions/checkout@") {
					continue
				}
				checkouts++
				perWorkflow[wf]++
				where := fmt.Sprintf("%s %s step %d", wf, jobName, i)

				got, ok := st.With["persist-credentials"]
				if !ok {
					t.Errorf("%s: checkout does not set persist-credentials", where)
				} else if got != false {
					t.Errorf("%s: persist-credentials is %v, want false", where, got)
				}

				if parts := strings.SplitN(st.Uses, "@", 2); len(parts) != 2 || len(parts[1]) < 40 {
					t.Errorf("%s: checkout is not pinned to a full SHA: %q", where, st.Uses)
				}
				for k, v := range st.With {
					switch k {
					case "persist-credentials":
					case "fetch-depth":
						if v == 0 {
							sawFetchDepthZero[wf] = append(sawFetchDepthZero[wf], jobName)
						} else {
							t.Errorf("%s: fetch-depth is %v; only 0 is approved", where, v)
						}
					default:
						t.Errorf("%s: unexpected checkout input %q", where, k)
					}
				}

				if i+1 >= len(job.Steps) {
					t.Errorf("%s: checkout is the last step; the assertion is missing", where)
					continue
				}
				next := job.Steps[i+1]
				if next.Name != assertStepName {
					t.Errorf("%s: next step is %q, want %q", where, next.Name, assertStepName)
					continue
				}
				// Reject anything that is not a bare invocation.
				body := strings.TrimSpace(next.Run)
				if !runIsBareInvocation.MatchString(body) {
					t.Errorf("%s: assertion step runs %q, which is not a bare invocation of %s", where, body, assertScript)
					continue
				}
				assertions++
			}
		}
	}

	if checkouts != want.totalCheckouts {
		t.Errorf("found %d checkout steps, spec approves %d", checkouts, want.totalCheckouts)
	}
	if assertions != want.assertions {
		t.Errorf("found %d bare assertion invocations, spec approves %d", assertions, want.assertions)
	}
	for wf, n := range want.perWorkflow {
		if perWorkflow[wf] != n {
			t.Errorf("%s has %d checkouts, spec approves %d", wf, perWorkflow[wf], n)
		}
	}
	// fetch-depth: 0 is bound to the named jobs, not to a total.
	for wf, jobs := range want.fetchDepthZero {
		got := append([]string(nil), sawFetchDepthZero[wf]...)
		exp := append([]string(nil), jobs...)
		sort.Strings(got)
		sort.Strings(exp)
		if !reflect.DeepEqual(got, exp) {
			t.Errorf("%s: fetch-depth: 0 on jobs %v, spec approves %v", wf, got, exp)
		}
	}
	for wf := range sawFetchDepthZero {
		if _, ok := want.fetchDepthZero[wf]; !ok {
			t.Errorf("%s carries fetch-depth: 0 but the spec approves none there", wf)
		}
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
