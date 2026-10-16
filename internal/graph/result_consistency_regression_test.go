package graph

import (
	"encoding/json"
	"testing"
)

// A self-rehashed result does not become authenticated. But verify must still
// reject impossible cross-field relationships before printing PASS.
func TestVerifyReportRejectsContradictorySelfRehashedResult(t *testing.T) {
	baseline, err := Analyze(fixture())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Result)
	}{
		{"cross_scope_node", func(r *Result) { r.Nodes[0].ScopeID = "other-scope" }},
		{"invalid_finding_state", func(r *Result) { r.Findings[0].State = "secretly_confirmed" }},
		{"hypothesis_human_promotion", func(r *Result) {
			for i := range r.Findings {
				if r.Findings[i].State == "hypothesis" {
					r.Findings[i].HumanAssertion = true
					return
				}
			}
		}},
		{"unknown_finding_evidence", func(r *Result) { r.Findings[0].EvidenceIDs = []string{"ghost-ev"} }},
		{"nonexistent_attack_path_edge", func(r *Result) { r.AttackPaths[0].EdgeIDs = []string{"ghost-edge"} }},
		{"negative_evidence_on_confirmed", func(r *Result) { r.NegativeEvidence = []string{"edge1"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, e := json.Marshal(baseline)
			if e != nil {
				t.Fatal(e)
			}
			var altered Result
			if e = json.Unmarshal(raw, &altered); e != nil {
				t.Fatal(e)
			}
			tc.mutate(&altered)
			altered.SHA256 = ""
			unsigned, e := json.Marshal(altered)
			if e != nil {
				t.Fatal(e)
			}
			altered.SHA256 = sum(unsigned)
			forged, e := json.Marshal(altered)
			if e != nil {
				t.Fatal(e)
			}
			if err := VerifyReport(forged); err == nil {
				t.Fatal("self-rehashed internally contradictory report accepted")
			}
		})
	}
	raw, e := Encode(baseline)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyReport(raw); e != nil {
		t.Fatalf("valid original refused: %v", e)
	}
	if e = Replay(fixture(), raw); e != nil {
		t.Fatalf("valid replay refused: %v", e)
	}
}
