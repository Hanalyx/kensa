package evidence

import (
	"bytes"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// oscalARSchemaPath is the vendored official NIST OSCAL 1.0.6 Assessment
// Results JSON schema, used to validate everything ExportOSCAL emits.
const oscalARSchemaPath = "testdata/oscal-schema/oscal_assessment-results_1.0.6_schema.json"

// loadOSCALSchema compiles the vendored OSCAL 1.0.6 AR schema. It uses
// santhosh-tekuri/jsonschema (pure Go) because the OSCAL schema relies on
// ECMA-262 `\p{...}` Unicode regex that Go's stdlib regexp — and several
// other JSON-schema validators — cannot compile.
func loadOSCALSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open(oscalARSchemaPath)
	if err != nil {
		t.Fatalf("open OSCAL schema: %v", err)
	}
	defer func() { _ = f.Close() }()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("decode OSCAL schema: %v", err)
	}
	// The vendored OSCAL 1.0.6 schema is draft-07 and declares all 71 of its
	// named anchors via the draft-07 idiom `"$id": "#anchor-name"`. v6 does
	// not register that idiom, so every internal anchor `$ref` fails to
	// compile. Normalize in-memory to the equivalent 2020-12 form — rewrite
	// each fragment `$id` to `$anchor` and run the schema as 2020-12 — which
	// v6 supports natively. This is byte-pristine on disk (the vendored file
	// is untouched) and semantics-preserving: there are no tuple `items` to
	// trip `prefixItems`, path-based `#/definitions/...` refs resolve
	// unchanged, and the 3 `\p{...}` ECMA regexes (which fatally break Python
	// validators) compile fine in Go. The verified gate is the test below.
	normalizeOSCALAnchors(doc)
	if m, ok := doc.(map[string]any); ok {
		m["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	}
	const schemaID = "http://csrc.nist.gov/ns/oscal/1.0.6/oscal-ar-schema.json"
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaID, doc); err != nil {
		t.Fatalf("add OSCAL schema resource: %v", err)
	}
	s, err := c.Compile(schemaID)
	if err != nil {
		t.Fatalf("compile OSCAL schema: %v", err)
	}
	return s
}

// normalizeOSCALAnchors rewrites the draft-07 anchor idiom `"$id": "#name"`
// (used 71× in the OSCAL schema) to the 2020-12 `"$anchor": "name"` form, in
// place. The root `$id` (an absolute URI, no leading `#`) is left as the
// canonical resource id.
func normalizeOSCALAnchors(node any) {
	switch v := node.(type) {
	case map[string]any:
		if id, ok := v["$id"].(string); ok && len(id) > 1 && id[0] == '#' {
			v["$anchor"] = id[1:]
			delete(v, "$id")
		}
		for _, child := range v {
			normalizeOSCALAnchors(child)
		}
	case []any:
		for _, child := range v {
			normalizeOSCALAnchors(child)
		}
	}
}

// TestExportOSCAL_ValidatesAgainst106Schema is the OSCAL conformance gate. It
// (1) compiles the vendored official NIST OSCAL 1.0.6 Assessment Results
// schema — proving the vendored schema + the anchor normalization are usable
// for validation — and (2) validates the real bytes ExportOSCAL emits against
// it, including the regex-constrained fields (UUID v4, date-time, control-id
// tokens) a Go validator checks.
//
// It is a HARD gate: the v0.4.0 OSCAL enrichment fixed the two 1.0.6 gaps this
// gate originally caught (result.uuid is now RFC4122-valid; control-ids are
// the framework-prefixed "<FrameworkID>-<ControlID>" token form), so any
// future change that breaks 1.0.6 conformance fails the build here.
func TestExportOSCAL_ValidatesAgainst106Schema(t *testing.T) {
	schema := loadOSCALSchema(t) // proves the vendored 1.0.6 schema compiles
	if len(goldenFixtures) == 0 {
		t.Fatal("no golden envelope fixtures")
	}
	for _, fx := range goldenFixtures {
		t.Run(fx.name, func(t *testing.T) {
			b, err := ExportOSCAL(fx.envelope)
			if err != nil {
				t.Fatalf("ExportOSCAL: %v", err)
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				t.Fatalf("decode emitted OSCAL: %v", err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Errorf("emitted OSCAL is not valid OSCAL 1.0.6 AR:\n%v", err)
			}
		})
	}
}
