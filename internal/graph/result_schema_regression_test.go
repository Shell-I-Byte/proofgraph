package graph

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVerifyReportRejectsSelfRehashedInvalidResultShape(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/lab.json")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := Analyze(raw)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Result)
	}{
		{"node_type", func(r *Result) { r.Nodes[0].Type = "NOT_A_TYPE" }},
		{"node_id", func(r *Result) { r.Nodes[0].ID = "bad id" }},
		{"node_scope", func(r *Result) { r.Nodes[0].ScopeID = "wrong scope" }},
		{"negative_bytes", func(r *Result) { r.Evidence[0].Bytes = -1 }},
		{"too_many_bytes", func(r *Result) { r.Evidence[0].Bytes = MaxRawEvidence + 1 }},
		{"evidence_invalid_sha", func(r *Result) { r.Evidence[0].SHA256 = "not-a-hash" }},
		{"evidence_id", func(r *Result) { r.Evidence[0].ID = "bad id" }},
		{"input_digest", func(r *Result) { r.InputSHA256 = "not-a-hash" }},
		{"snapshot", func(r *Result) { r.Snapshot = "not-a-time" }},
		{"report_scope", func(r *Result) { r.ScopeID = "wrong scope" }},
		{"missing_link", func(r *Result) { r.MissingLinks = []string{"wrong ref"} }},
		{"negative_reference", func(r *Result) { r.NegativeEvidence = []string{"wrong ref"} }},
		{"node_limit", func(r *Result) { r.Nodes = make([]Node, maxNodes+1) }},
		{"evidence_limit", func(r *Result) { r.Evidence = make([]EvidenceRecord, maxEvidence+1) }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var r Result
			// Each new JSON instance is independent, so no test may accidentally
			// influence a later mutation through shared backing slices.
			serialized, err := json.Marshal(baseline)
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(serialized, &r); err != nil {
				t.Fatal(err)
			}
			tt.mutate(&r)
			r.SHA256 = ""
			canonical, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			r.SHA256 = sum(canonical)
			forged, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err = VerifyReport(forged); err == nil {
				t.Fatalf("accepted schema-invalid self-rehashed report: %s", tt.name)
			}
		})
	}
	good, err := Encode(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyReport(good); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	if err = Replay(raw, good); err != nil {
		t.Fatalf("valid report replay rejected: %v", err)
	}
}
