package coverage

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
)

// NIST800171Framework is the framework id this report answers for. Every other
// framework keeps the numerator-only policy: kensa has no catalog for them, and
// inventing a denominator would measure the standard rather than the product.
const NIST800171Framework = "nist_800_171"

//go:embed embedded/nist_800_171_r2.json
var nist800171Raw []byte

type objectiveEntry struct {
	Family string `json:"family"`
	// Tier is a reviewer's judgment about whether a host scanner can evidence
	// this objective at all. It is not a verdict about any host.
	//
	//	T1  the host alone answers it
	//	T2  the host observes, the operator declares the expected set
	//	T3  feasible only on some identity architectures
	//	T4  policy, procedure, training, interview. Not technically evidenceable
	//	""  nobody has decided. See the unclassified bucket, and KN-KN-029.
	Tier string `json:"tier"`
	// Verdict is the reviewed mapping outcome, and is the numerator. It is
	// deliberately separate from Tier: a tier says whether an objective CAN be
	// evidenced, a verdict says whether it IS.
	Verdict string `json:"verdict"`
}

type objectiveCatalog struct {
	SourceDigest        string                    `json:"_source_digest"`
	Revision            string                    `json:"revision"`
	Total               int                       `json:"total"`
	BoundaryFamilies    []string                  `json:"boundary_families"`
	IdentityConditional []string                  `json:"identity_conditional"`
	Objectives          map[string]objectiveEntry `json:"objectives"`
}

// objectiveCatalogs keys every framework that ships an objective catalog by
// its framework id. The dispatch asks this map whether a denominator is
// possible, rather than naming a framework: a framework with a catalog gets
// one, a framework without keeps the numerator-only policy. Adding the next
// catalog is a data change plus one entry here, not a new branch in the CLI.
var objectiveCatalogs = map[string]objectiveCatalog{
	NIST800171Framework: mustLoadCatalog(nist800171Raw),
}

func mustLoadCatalog(raw []byte) objectiveCatalog {
	var c objectiveCatalog
	if err := json.Unmarshal(raw, &c); err != nil {
		panic("coverage: embedded objective catalog is unreadable: " + err.Error())
	}
	return c
}

// HasObjectiveCatalog reports whether this framework can be given a
// denominator. Callers use it instead of comparing against a framework name,
// so the question stays "is there a catalog" rather than "is it this one".
func HasObjectiveCatalog(framework string) bool {
	_, ok := objectiveCatalogs[framework]
	return ok
}

// nist800171Catalog is the one catalog that exists today. It is fetched
// through the map so the map is the single source of truth.
var nist800171Catalog = objectiveCatalogs[NIST800171Framework]

// Architecture is the identity architecture a denominator is computed for.
// It exists because seven objectives are answerable on a host whose accounts
// are local and not on one whose authority lives in a directory, which is why
// DEC-1 refused a single published percentage.
type Architecture string

const (
	// ArchLocalAccounts: the host owns its accounts, so the operator can
	// declare an authorized set and kensa can compare against the host.
	ArchLocalAccounts Architecture = "local_accounts"
	// ArchDirectoryJoined: the authoritative user list is off-box. Kensa can
	// still evidence that the host defers correctly and cannot be bypassed,
	// which is a partial with a handoff (DEC-2), not a satisfied objective.
	ArchDirectoryJoined Architecture = "directory_joined"
	// ArchUnknown is used when no scan report was supplied, and is the reason
	// the static report shows both ceilings rather than choosing.
	ArchUnknown Architecture = "unknown"
)

// Buckets is the denominator, and the two groups removed to reach it.
//
// The three counts are reported together everywhere because the assessable
// number alone is not interpretable: 320 measures the standard, and the gap
// between 320 and Assessable is most of what 800-171 asks for. Publishing a
// percentage without Boundary beside it would flatter whoever has the larger
// numerator.
type Buckets struct {
	// Assessable is the denominator: objectives a host scanner can evidence
	// on this architecture.
	Assessable int `json:"assessable"`
	// Boundary is objectives no configuration scanner can evidence, ours or
	// anyone's — interviews, records, buildings, and organizational decisions.
	Boundary int `json:"boundary"`
	// Unclassified is objectives nobody has dispositioned. Never folded into
	// either of the others; see KN-KN-029.
	Unclassified int `json:"unclassified"`
	// Total is the whole of the revision, and must equal the sum.
	Total int `json:"total"`
}

// Ceiling is one architecture's denominator together with the counts measured
// against it. The counts belong here rather than beside them, because a
// numerator computed for one architecture is wrong for the other: three of the
// satisfied objectives are T3, so a joined fleet cannot reach them.
type Ceiling struct {
	Buckets   Buckets `json:"buckets"`
	Satisfied int     `json:"satisfied"`
	Partial   int     `json:"partial"`
	NoRule    int     `json:"no_rule"`
}

// NIST800171Report is the operator-facing shape. It deliberately has no single
// "percent" field: a caller that wants one must divide, and to divide it must
// hold the denominator, which is the point.
type NIST800171Report struct {
	Framework    string       `json:"framework"`
	Revision     string       `json:"revision"`
	Architecture Architecture `json:"architecture"`
	// Ceilings is populated only when Architecture is unknown, and carries
	// one entry per architecture so neither is presented as the answer.
	Ceilings map[Architecture]Ceiling `json:"ceilings,omitempty"`
	// Buckets is populated only when the architecture is known.
	Buckets *Buckets `json:"buckets,omitempty"`
	// Satisfied counts objectives a reviewed mapping records as satisfied
	// AND that are assessable on this architecture. It is mapping status,
	// never scan posture: a rule failing on a host does not reduce it.
	Satisfied int `json:"satisfied"`
	// Partial is real evidence with a stated gap, reported separately so it
	// is never quietly added to Satisfied.
	Partial int `json:"partial"`
	// NoRule is assessable objectives with no rule at all — the corpus gap,
	// as distinct from the boundary.
	NoRule int `json:"no_rule"`
	// UnclassifiedIDs lets a reader audit the bucket rather than trust it.
	UnclassifiedIDs []string `json:"unclassified_ids"`
	// HostsScanned is 0 for a static report.
	HostsScanned int `json:"hosts_scanned"`
	// SourceDigest ties the numbers to the reviewed corpus they came from.
	SourceDigest string `json:"source_digest"`
}

// isBoundaryFamily reports whether a family is one NIST writes as
// organizational, where no objective is host-evidenceable.
func (c objectiveCatalog) isBoundaryFamily(fam string) bool {
	for _, b := range c.BoundaryFamilies {
		if b == fam {
			return true
		}
	}
	return false
}

// assessable reports whether an objective counts toward the denominator on the
// given architecture.
//
// T3 is the whole reason this takes an architecture. Those objectives are
// answerable when the host owns its accounts and not when a directory does, so
// on a joined fleet they leave the denominator rather than sitting in it as
// permanent failures.
func (c objectiveCatalog) assessable(e objectiveEntry, arch Architecture) bool {
	switch e.Tier {
	case "T1", "T2":
		return true
	case "T3":
		return arch != ArchDirectoryJoined
	default:
		return false
	}
}

// bucketize splits the catalog for one architecture.
func (c objectiveCatalog) bucketize(arch Architecture) (Buckets, []string) {
	var b Buckets
	unclassified := []string{}
	for id, e := range c.Objectives {
		switch {
		case c.assessable(e, arch):
			b.Assessable++
		case e.Tier == "T4" || c.isBoundaryFamily(e.Family):
			b.Boundary++
		case e.Tier == "T3":
			// Assessable on local accounts, a handoff here. It is still a
			// thing a scanner can speak to, so it is boundary only in the
			// sense that this fleet cannot close it.
			b.Boundary++
		default:
			b.Unclassified++
			unclassified = append(unclassified, id)
		}
	}
	b.Total = c.Total
	sort.Strings(unclassified)
	return b, unclassified
}

// tally counts reviewed verdicts over the objectives assessable on one
// architecture. Objectives outside the denominator are not counted at all,
// rather than counted as failures: an objective a fleet's architecture puts
// out of reach is not a gap in the corpus.
func (c objectiveCatalog) tally(arch Architecture) (satisfied, partial, noRule int) {
	for _, e := range c.Objectives {
		if !c.assessable(e, arch) {
			continue
		}
		switch e.Verdict {
		case "satisfies":
			satisfied++
		case "partial":
			partial++
		case "no-rule", "":
			noRule++
		}
	}
	return
}

// ComputeNIST800171 builds the report. arch of ArchUnknown produces the static
// form, which renders both ceilings.
func ComputeNIST800171(arch Architecture, hostsScanned int) NIST800171Report {
	c := nist800171Catalog
	r := NIST800171Report{
		Framework:    NIST800171Framework,
		Revision:     c.Revision,
		Architecture: arch,
		HostsScanned: hostsScanned,
		SourceDigest: c.SourceDigest,
	}

	if arch == ArchUnknown {
		r.Ceilings = map[Architecture]Ceiling{}
		for _, a := range []Architecture{ArchLocalAccounts, ArchDirectoryJoined} {
			b, unc := c.bucketize(a)
			sat, part, none := c.tally(a)
			r.Ceilings[a] = Ceiling{Buckets: b, Satisfied: sat, Partial: part, NoRule: none}
			r.UnclassifiedIDs = unc
		}
		return r
	}

	b, unc := c.bucketize(arch)
	r.Buckets = &b
	r.UnclassifiedIDs = unc
	r.Satisfied, r.Partial, r.NoRule = c.tally(arch)
	return r
}

// ArchitectureFromCapabilities decides a fleet's architecture from the
// per-host capability maps a scan already emits.
//
// Any joined host makes the fleet joined. That is deliberate and conservative:
// the identity objectives cannot be satisfied for the joined hosts, and a
// denominator that ignored them would report a ceiling the fleet cannot reach.
func ArchitectureFromCapabilities(caps []map[string]bool) Architecture {
	if len(caps) == 0 {
		return ArchUnknown
	}
	for _, c := range caps {
		if c["directory_joined"] {
			return ArchDirectoryJoined
		}
	}
	return ArchLocalAccounts
}

// String renders the percentage the way it is allowed to be quoted: never
// alone.
func (b Buckets) String() string {
	return fmt.Sprintf("%d assessable, %d boundary, %d unclassified, of %d",
		b.Assessable, b.Boundary, b.Unclassified, b.Total)
}
