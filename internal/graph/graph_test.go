package graph

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func fixture() []byte {
	return []byte(`{
 "schema":"proofgraph.security-ir/v1", "authorization":{"scope_id":"lab-1","granted_by":"owner","valid_from":"2026-10-01T00:00:00Z","valid_until":"2026-10-31T00:00:00Z"},
 "snapshot":"2026-10-09T06:00:00Z",
 "nodes":[{"id":"origin","type":"identity","scope_id":"lab-1"},{"id":"web","type":"service","scope_id":"lab-1"},{"id":"vault","type":"asset","scope_id":"lab-1"},{"id":"vault2","type":"asset","scope_id":"lab-1"}],
 "evidence":[{"id":"ev1","source":"synthetic","data_base64":"c3ludGhldGljIGV2aWRlbmNl"}],
 "edges":[
 {"id":"edge1","from":"origin","to":"web","kind":"access","state":"confirmed","evidence_ids":["ev1"],"observed_at":"2026-10-08T00:00:00Z","verified_by":"analyst"},
 {"id":"edge2","from":"web","to":"vault","kind":"access","state":"confirmed","evidence_ids":["ev1"],"observed_at":"2026-10-08T00:00:00Z","verified_by":"analyst"},
 {"id":"edge3","from":"web","to":"vault2","kind":"access","state":"hypothesis","evidence_ids":["ev1"],"observed_at":"2026-10-08T00:00:00Z"},
 {"id":"edge4","from":"web","to":"vault","kind":"access","state":"disproven","evidence_ids":["ev1"],"observed_at":"2026-10-08T00:00:00Z"}],
 "entry_nodes":["origin"],"target_nodes":["vault","vault2"]
 }`)
}
func TestPositiveAnalysisReplay(t *testing.T) {
	raw := fixture()
	r, e := Analyze(raw)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.AttackPaths) != 1 || r.AttackPaths[0].To != "vault" {
		t.Fatalf("paths: %+v", r.AttackPaths)
	}
	if len(r.GraphCuts) != 2 || len(r.Contradictions) != 1 || r.BlastRadius["origin"] != 1 {
		t.Fatalf("graph metrics: %+v", r)
	}
	if len(r.NegativeEvidence) != 1 || r.NegativeEvidence[0] != "edge4" || len(r.MissingLinks) != 1 || r.InformationGain[0].PossibleNewPaths != 1 {
		t.Fatalf("evidence semantics: %+v", r)
	}
	if len(r.Evidence) != 1 || r.Evidence[0].Bytes != 18 {
		t.Fatalf("provenance: %+v", r.Evidence)
	}
	b, e := Encode(r)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte("c3ludGh")) || bytes.Contains(b, []byte("synthetic evidence")) {
		t.Fatal("raw evidence leaked")
	}
	if e = VerifyReport(b); e != nil {
		t.Fatal(e)
	}
	if e = Replay(raw, b); e != nil {
		t.Fatal(e)
	}
	c, e := Analyze(raw)
	if e != nil {
		t.Fatal(e)
	}
	d, _ := Encode(c)
	if !bytes.Equal(b, d) {
		t.Fatal("nondeterministic JSON")
	}
	var obj map[string]any
	if e = json.Unmarshal(b, &obj); e != nil {
		t.Fatal(e)
	}
	obj["scope_id"] = "forged"
	tampered, _ := json.Marshal(obj)
	if VerifyReport(tampered) == nil {
		t.Fatal("tampered report accepted")
	}
	changed := bytes.Replace(raw, []byte("vault2"), []byte("vaultX"), 1)
	if Replay(changed, b) == nil {
		t.Fatal("modified source accepted")
	}
}
func TestNegativeMalformedBoundary(t *testing.T) {
	base := fixture()
	tests := map[string][]byte{
		"duplicate top-level":         []byte(`{"schema":"a","schema":"b"}`),
		"duplicate nested":            bytes.Replace(base, []byte(`"scope_id":"lab-1"`), []byte(`"scope_id":"lab-1","scope_id":"lab-2"`), 1),
		"unknown field":               bytes.Replace(base, []byte(`"entry_nodes":`), []byte(`"unknown":1,"entry_nodes":`), 1),
		"wrong version":               bytes.Replace(base, []byte(Schema), []byte("proofgraph.security-ir/v3"), 1),
		"wrong scope":                 bytes.Replace(base, []byte(`"scope_id":"lab-1"`), []byte(`"scope_id":"different"`), 1),
		"expired authorization":       bytes.Replace(base, []byte(`2026-10-31T00:00:00Z`), []byte(`2026-10-07T00:00:00Z`), 1),
		"future edge":                 bytes.Replace(base, []byte(`2026-10-08T00:00:00Z`), []byte(`2026-11-08T00:00:00Z`), 1),
		"unknown evidence":            bytes.Replace(base, []byte(`"evidence_ids":["ev1"]`), []byte(`"evidence_ids":["bad"]`), 1),
		"unattested confirmed":        bytes.Replace(base, []byte(`,"verified_by":"analyst"`), []byte(``), 1),
		"AI cannot verify hypothesis": bytes.Replace(base, []byte(`"state":"hypothesis","evidence_ids":["ev1"]`), []byte(`"state":"hypothesis","evidence_ids":["ev1"],"verified_by":"ai"`), 1),
		"unknown edge vertex":         bytes.Replace(base, []byte(`"to":"vault2"`), []byte(`"to":"outside"`), 1),
		"bad base64":                  bytes.Replace(base, []byte(`"c3ludGhldGljIGV2aWRlbmNl"`), []byte(`"***"`), 1),
		"extra document":              append(append([]byte{}, base...), []byte(` {}`)...),
		"invalid UTF8":                append(append([]byte{}, base...), 0xff),
		"oversized":                   bytes.Repeat([]byte("a"), MaxInput+1),
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			if _, e := Analyze(b); e == nil {
				t.Fatal("malformed input accepted")
			}
		})
	}
}
func TestStateFalsification(t *testing.T) {
	raw := fixture()
	// Hypothesis may be missing, but cannot become a confirmed path without attestation.
	r, e := Analyze(raw)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range r.AttackPaths {
		if p.To == "vault2" {
			t.Fatal("hypothesis promoted to path")
		}
	}
	// Unsupported JSON null struct has to be rejected even though the stdlib decoder accepts it.
	if _, e := Analyze([]byte(`null`)); e == nil {
		t.Fatal("null accepted")
	}
	// Untrusted free-text control chars must not be reflected.
	hostile := bytes.Replace(raw, []byte(`"id":"origin"`), []byte(`"id":"origin\\nspoof"`), 1)
	if _, e := Analyze(hostile); e == nil {
		t.Fatal("hostile ID accepted")
	}
}
func TestConcurrentDeterminism(t *testing.T) {
	raw := fixture()
	r, e := Analyze(raw)
	if e != nil {
		t.Fatal(e)
	}
	want, _ := Encode(r)
	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := Analyze(raw)
			if e != nil {
				errCh <- e
				return
			}
			b, e := Encode(r)
			if e != nil {
				errCh <- e
				return
			}
			if !bytes.Equal(b, want) {
				errCh <- json.Unmarshal([]byte("!"), new(interface{}))
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatal(e)
	}
}
func FuzzAnalyze(f *testing.F) {
	f.Add(fixture())
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxInput {
			return
		}
		r, e := Analyze(b)
		if e == nil {
			out, _ := Encode(r)
			if e = VerifyReport(out); e != nil {
				t.Fatalf("successful graph generated invalid report: %v", e)
			}
			if strings.Contains(string(out), "data_base64") {
				t.Fatal("raw evidence field leaked")
			}
		}
	})
}

// Boundary graph tests ensure that bounded BFS does not enumerate exponential paths.
func TestDenseGraphAndLimits(t *testing.T) {
	x := Input{Schema: Schema,
		Authorization: Authorization{ScopeID: "lab-1", GrantedBy: "owner", ValidFrom: "2026-10-01T00:00:00Z", ValidUntil: "2026-10-31T00:00:00Z"},
		Snapshot:      "2026-10-09T00:00:00Z", EntryNodes: []string{"n000"}, TargetNodes: []string{"n100"},
		Evidence: []Evidence{{ID: "proof", Source: "synthetic", DataBase64: "bGFi"}},
	}
	for i := 0; i < 128; i++ {
		x.Nodes = append(x.Nodes, Node{ID: fmt.Sprintf("n%03d", i), Type: "asset", ScopeID: "lab-1"})
	}
	for i := 1; i <= 512; i++ {
		from := fmt.Sprintf("n%03d", (i-1)%127)
		to := fmt.Sprintf("n%03d", i%127)
		if from == to {
			to = "n127"
		}
		x.Edges = append(x.Edges, Edge{ID: fmt.Sprintf("e%03d", i), From: from, To: to, Kind: "access", State: "confirmed", EvidenceIDs: []string{"proof"}, ObservedAt: "2026-10-08T00:00:00Z", VerifiedBy: "human"})
	}
	b, e := json.Marshal(x)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Analyze(b); e != nil {
		t.Fatalf("maximum edge count refused: %v", e)
	}
	x.Edges = append(x.Edges, x.Edges[0])
	x.Edges[len(x.Edges)-1].ID = "e513"
	b, _ = json.Marshal(x)
	if _, e := Analyze(b); e == nil {
		t.Fatal("accepted too many edges")
	}
}

// Regression PG-069-001: encoding/json v1 matches struct members
// case-insensitively, which could override an authorization or confirmation.
func TestStrictExactJSONMemberNames(t *testing.T) {
	base := fixture()
	tests := map[string][]byte{
		"root schema case":                             bytes.Replace(base, []byte(`"schema":`), []byte(`"Schema":`), 1),
		"authorization scope case":                     bytes.Replace(base, []byte(`"scope_id":"lab-1"`), []byte(`"Scope_ID":"lab-1"`), 1),
		"authorization double-key with different case": bytes.Replace(base, []byte(`"scope_id":"lab-1"`), []byte(`"scope_id":"lab-1","Scope_ID":"lab-1"`), 1),
		"edge state case":                              bytes.Replace(base, []byte(`"state":"hypothesis"`), []byte(`"State":"confirmed","state":"hypothesis"`), 1),
		"edge verification case":                       bytes.Replace(base, []byte(`"verified_by":"analyst"`), []byte(`"Verified_By":"analyst"`), 1),
		"evidence payload case":                        bytes.Replace(base, []byte(`"data_base64":"c3ludGhldGljIGV2aWRlbmNl"`), []byte(`"Data_Base64":"c3ludGhldGljIGV2aWRlbmNl"`), 1),
		"node type case":                               bytes.Replace(base, []byte(`"type":"identity"`), []byte(`"Type":"identity"`), 1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Analyze(raw); err == nil {
				t.Fatal("case-variant field name accepted")
			}
		})
	}
	positive, err := Analyze(base)
	if err != nil {
		t.Fatalf("valid graph refused: %v", err)
	}
	encoded, err := Encode(positive)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReport(encoded); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(encoded, []byte(`"scope_id":`), []byte(`"Scope_ID":`), 1)
	if err := VerifyReport(changed); err == nil {
		t.Fatal("case-variant report member accepted")
	}
	if err := Replay(base, changed); err == nil {
		t.Fatal("case-variant replay report accepted")
	}
}

// Regression BUG-PG-094-001: optional verification is forbidden on any
// non-confirmed edge, even when JSON's value is null or an empty string.
// All JSON properties and array fields are non-nullable in the versioned IR.
func TestStrictVerificationPresenceAndNullSchema(t *testing.T) {
	base := fixture()
	hostile := map[string][]byte{
		"hypothesis explicit null":  bytes.Replace(base, []byte(`"state":"hypothesis","evidence_ids"`), []byte(`"state":"hypothesis","verified_by":null,"evidence_ids"`), 1),
		"hypothesis empty verifier": bytes.Replace(base, []byte(`"state":"hypothesis","evidence_ids"`), []byte(`"state":"hypothesis","verified_by":"","evidence_ids"`), 1),
		"observed explicit null":    bytes.Replace(base, []byte(`"state":"hypothesis","evidence_ids"`), []byte(`"state":"observed","verified_by":null,"evidence_ids"`), 1),
		"disproven empty verifier":  bytes.Replace(base, []byte(`"state":"disproven","evidence_ids"`), []byte(`"state":"disproven","verified_by":"","evidence_ids"`), 1),
		"confirmed null verifier":   bytes.Replace(base, []byte(`"verified_by":"analyst"`), []byte(`"verified_by":null`), 1),
		"null snapshot":             bytes.Replace(base, []byte(`"snapshot":"2026-10-09T06:00:00Z"`), []byte(`"snapshot":null`), 1),
	}
	for name, raw := range hostile {
		t.Run(name, func(t *testing.T) {
			if _, err := Analyze(raw); err == nil {
				t.Fatal("schema-invalid verification/property accepted")
			}
		})
	}
	// The report verifier must not accept a schema-invalid null array even
	// when the unkeyed SHA-256 has been recomputed by the adversarial author.
	r, err := Analyze(base)
	if err != nil {
		t.Fatal(err)
	}
	r.Limitations = nil
	r.SHA256 = ""
	stable, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	r.SHA256 = sum(stable)
	serialized, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyReport(serialized); err == nil {
		t.Fatal("rehashed report with null limitations accepted")
	}
	// Positive controls remain valid: absent verifier on hypotheses and a
	// nonempty string verifier on confirmed edges.
	if _, err := Analyze(base); err != nil {
		t.Fatalf("valid evidence refused: %v", err)
	}
}
