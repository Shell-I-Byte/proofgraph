package graph

import (
	"encoding/json"
	"testing"
)

// A deliberately recomputed unkeyed SHA256 cannot justify fabricated
// remediation impact, information gain, blast radius, or contradictions.
func TestVerifyReportRejectsFabricatedDerivedMetrics(t *testing.T) {
	original, err := Analyze(fixture())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Result)
	}{
		{"unknown_graph_cut_edge", func(r *Result) { r.GraphCuts = []Counterfactual{{RemovedEdge: "ghost-edge", DisconnectedTargets: 1}} }},
		{"nonconfirmed_graph_cut_edge", func(r *Result) { r.GraphCuts = []Counterfactual{{RemovedEdge: "edge3", DisconnectedTargets: 1}} }},
		{"overstated_graph_cut_impact", func(r *Result) { r.GraphCuts = []Counterfactual{{RemovedEdge: "edge2", DisconnectedTargets: 999}} }},
		{"unknown_information_gain", func(r *Result) { r.InformationGain = []InfoGain{{EdgeID: "ghost-edge", PossibleNewPaths: 1}} }},
		{"confirmed_information_gain", func(r *Result) { r.InformationGain = []InfoGain{{EdgeID: "edge1", PossibleNewPaths: 1}} }},
		{"negative_blast_radius", func(r *Result) { r.BlastRadius["origin"] = -1 }},
		{"unknown_blast_radius_node", func(r *Result) { r.BlastRadius["ghost-node"] = 1 }},
		{"bogus_contradiction", func(r *Result) { r.Contradictions = [][]string{{"edge1", "edge3"}} }},
		{"missing_negative_evidence", func(r *Result) { r.NegativeEvidence = []string{} }},
		{"missing_hypothesis_link", func(r *Result) { r.MissingLinks = []string{} }},
		{"missing_contradiction", func(r *Result) { r.Contradictions = [][]string{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var r Result
			if err = json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&r)
			r.SHA256 = ""
			unsigned, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			r.SHA256 = sum(unsigned)
			payload, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err = VerifyReport(payload); err == nil {
				t.Fatalf("accepted self-rehashed fabricated %s", tc.name)
			}
		})
	}
	payload, err := Encode(original)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyReport(payload); err != nil {
		t.Fatalf("rejects authentic local report: %s", err)
	}
	if err = Replay(fixture(), payload); err != nil {
		t.Fatalf("replay broken: %s", err)
	}
}
