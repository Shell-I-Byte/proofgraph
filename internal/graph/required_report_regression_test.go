package graph

import (
	"encoding/json"
	"testing"
)

// BUG-PG-108-001: removing a required report member must not become
// acceptable merely by recomputing an unkeyed, self-consistent checksum.
func TestVerifyReportRejectsMissingRequiredMembers(t *testing.T) {
	base, err := Analyze(fixture())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReport(encoded); err != nil {
		t.Fatalf("positive: %v", err)
	}
	for _, field := range []string{"nodes", "evidence", "findings", "attack_paths", "negative_evidence", "contradictions", "missing_links", "information_gain", "blast_radius", "graph_cuts", "limitations"} {
		t.Run(field, func(t *testing.T) {
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &doc); err != nil {
				t.Fatal(err)
			}
			delete(doc, field)
			partial, _ := json.Marshal(doc)
			var canonical Result
			if err := json.Unmarshal(partial, &canonical); err != nil {
				t.Fatal(err)
			}
			canonical.SHA256 = ""
			digestInput, _ := json.Marshal(canonical)
			doc["sha256"], _ = json.Marshal(sum(digestInput))
			forged, _ := json.Marshal(doc)
			if err := VerifyReport(forged); err == nil {
				t.Fatal("accepted report with missing required field and recomputed digest")
			}
			if err := Replay(fixture(), forged); err == nil {
				t.Fatal("replay accepted incomplete report")
			}
		})
	}
}
