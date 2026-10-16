// Package graph implements an offline evidence-first security graph evaluator.
// No method in this package initiates a network request.
package graph

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const Schema = "proofgraph.security-ir/v1"
const ResultSchema = "proofgraph.result/v1"
const MaxInput = 8 << 20
const MaxRawEvidence = 2 << 20
const maxNodes = 256
const maxEdges = 512
const maxEvidence = 256
const maxPathDepth = 8
const maxPaths = 16

// No free-text raw logs/URLs/credentials are admitted into graph entities.
// Human approvals are input assertions, never cryptographically verified identities.
type Authorization struct {
	ScopeID    string `json:"scope_id"`
	GrantedBy  string `json:"granted_by"`
	ValidFrom  string `json:"valid_from"`
	ValidUntil string `json:"valid_until"`
}
type Node struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	ScopeID string `json:"scope_id"`
}
type Evidence struct {
	ID         string `json:"id"`
	Source     string `json:"source"`
	DataBase64 string `json:"data_base64"`
}
type Edge struct {
	ID          string   `json:"id"`
	From        string   `json:"from"`
	To          string   `json:"to"`
	Kind        string   `json:"kind"`
	State       string   `json:"state"`
	EvidenceIDs []string `json:"evidence_ids"`
	ObservedAt  string   `json:"observed_at"`
	VerifiedBy  string   `json:"verified_by,omitempty"`
}
type Input struct {
	Schema        string        `json:"schema"`
	Authorization Authorization `json:"authorization"`
	Snapshot      string        `json:"snapshot"`
	Nodes         []Node        `json:"nodes"`
	Evidence      []Evidence    `json:"evidence"`
	Edges         []Edge        `json:"edges"`
	EntryNodes    []string      `json:"entry_nodes"`
	TargetNodes   []string      `json:"target_nodes"`
}
type EvidenceRecord struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	Source string `json:"source"`
}
type Finding struct {
	EdgeID         string   `json:"edge_id"`
	From           string   `json:"from"`
	To             string   `json:"to"`
	Kind           string   `json:"kind"`
	State          string   `json:"state"`
	EvidenceIDs    []string `json:"evidence_ids"`
	HumanAssertion bool     `json:"human_assertion"`
}
type Path struct {
	From    string   `json:"from"`
	To      string   `json:"to"`
	EdgeIDs []string `json:"edge_ids"`
}
type Counterfactual struct {
	RemovedEdge         string `json:"removed_edge"`
	DisconnectedTargets int    `json:"disconnected_targets"`
}
type InfoGain struct {
	EdgeID           string `json:"edge_id"`
	PossibleNewPaths int    `json:"possible_new_paths"`
}
type Result struct {
	Schema           string           `json:"schema"`
	SourceSchema     string           `json:"source_schema"`
	InputSHA256      string           `json:"input_sha256"`
	ScopeID          string           `json:"scope_id"`
	Snapshot         string           `json:"snapshot"`
	Nodes            []Node           `json:"nodes"`
	Evidence         []EvidenceRecord `json:"evidence"`
	Findings         []Finding        `json:"findings"`
	AttackPaths      []Path           `json:"attack_paths"`
	NegativeEvidence []string         `json:"negative_evidence"`
	Contradictions   [][]string       `json:"contradictions"`
	MissingLinks     []string         `json:"missing_links"`
	InformationGain  []InfoGain       `json:"information_gain"`
	BlastRadius      map[string]int   `json:"blast_radius"`
	GraphCuts        []Counterfactual `json:"graph_cuts"`
	Limitations      []string         `json:"limitations"`
	SHA256           string           `json:"sha256"`
}

func validID(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, b := range []byte(s) {
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-' || b == '.') {
			return false
		}
	}
	return true
}
func in(s string, allowed ...string) bool {
	for _, v := range allowed {
		if s == v {
			return true
		}
	}
	return false
}

// Go's time.Parse(time.RFC3339, ...) intentionally accepts some inputs
// excluded by RFC 3339 section 5.6: single-digit hour fields, decimal
// commas and numeric offsets such as +24:00 or +00:60. Security IR uses a
// strict wire contract for authorization, snapshot and evidence timestamps.
var strictRFC3339 = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$`)

func ts(s string) (time.Time, error) {
	if !strictRFC3339.MatchString(s) {
		return time.Time{}, errors.New("invalid timestamp")
	}
	if s[len(s)-1] != 'Z' {
		offset := s[len(s)-6:]
		hour := int(offset[1]-'0')*10 + int(offset[2]-'0')
		minute := int(offset[4]-'0')*10 + int(offset[5]-'0')
		if hour > 23 || minute > 59 {
			return time.Time{}, errors.New("invalid timestamp")
		}
	}
	t, e := time.Parse(time.RFC3339, s)
	if e != nil {
		return time.Time{}, errors.New("invalid timestamp")
	}
	return t, nil
}
func sum(b []byte) string { x := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(x[:]) }

// checkValue consumes one JSON value and rejects duplicate member names at all depths.
func checkValue(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	v, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch v {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			keyToken, e := d.Token()
			if e != nil {
				return e
			}
			k, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if seen[k] {
				return errors.New("duplicate JSON object key")
			}
			seen[k] = true
			if e = checkValue(d); e != nil {
				return e
			}
		}
		_, e = d.Token()
		return e
	case '[':
		for d.More() {
			if e = checkValue(d); e != nil {
				return e
			}
		}
		_, e = d.Token()
		return e
	default:
		return errors.New("invalid JSON delimiter")
	}
}
func strictJSON(b []byte, v interface{}) error {
	if len(b) == 0 || len(b) > MaxInput {
		return errors.New("invalid JSON size")
	}
	if !utf8.Valid(b) {
		return errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := checkValue(d); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	if e := exactJSONNames(b, reflect.TypeOf(v)); e != nil {
		return e
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return errors.New("invalid JSON schema or type")
	}
	if e := d.Decode(new(interface{})); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func Validate(b []byte) (Input, []EvidenceRecord, error) {
	var x Input
	if e := strictJSON(b, &x); e != nil {
		return x, nil, e
	}
	if x.Schema != Schema {
		return x, nil, errors.New("unsupported schema")
	}
	a := x.Authorization
	if !validID(a.ScopeID) || !validID(a.GrantedBy) {
		return x, nil, errors.New("authorization scope or grantor invalid")
	}
	start, e := ts(a.ValidFrom)
	if e != nil {
		return x, nil, e
	}
	end, e := ts(a.ValidUntil)
	if e != nil {
		return x, nil, e
	}
	snap, e := ts(x.Snapshot)
	if e != nil {
		return x, nil, e
	}
	if start.After(snap) || end.Before(snap) || !end.After(start) {
		return x, nil, errors.New("snapshot outside authorization interval")
	}
	if x.Nodes == nil || x.Edges == nil || x.Evidence == nil || x.EntryNodes == nil || x.TargetNodes == nil {
		return x, nil, errors.New("missing/null graph arrays")
	}
	if len(x.Nodes) == 0 || len(x.Nodes) > maxNodes || len(x.Edges) > maxEdges || len(x.Evidence) > maxEvidence {
		return x, nil, errors.New("graph resource limit")
	}
	nodes := map[string]bool{}
	for _, n := range x.Nodes {
		if !validID(n.ID) || !in(n.Type, "asset", "identity", "service", "control", "finding") || n.ScopeID != a.ScopeID || nodes[n.ID] {
			return x, nil, errors.New("invalid or duplicate node / out-of-scope node")
		}
		nodes[n.ID] = true
	}
	for _, arr := range [][]string{x.EntryNodes, x.TargetNodes} {
		if len(arr) == 0 || len(arr) > 4 {
			return x, nil, errors.New("entry/target limit")
		}
		seen := map[string]bool{}
		for _, id := range arr {
			if !nodes[id] || seen[id] {
				return x, nil, errors.New("unknown or duplicate entry/target")
			}
			seen[id] = true
		}
	}
	ev := map[string]bool{}
	records := make([]EvidenceRecord, 0, len(x.Evidence))
	total := 0
	for _, v := range x.Evidence {
		if !validID(v.ID) || ev[v.ID] || !in(v.Source, "synthetic", "authorized_collection") {
			return x, nil, errors.New("invalid evidence record")
		}
		ev[v.ID] = true
		// Decode without allocating arbitrary unbounded binary blobs.
		if len(v.DataBase64) > base64.StdEncoding.EncodedLen(MaxRawEvidence) {
			return x, nil, errors.New("evidence too large")
		}
		raw, e := base64.StdEncoding.Strict().DecodeString(v.DataBase64)
		if e != nil || len(raw) == 0 || len(raw) > MaxRawEvidence {
			return x, nil, errors.New("invalid evidence payload")
		}
		total += len(raw)
		if total > MaxInput {
			return x, nil, errors.New("aggregate evidence limit")
		}
		records = append(records, EvidenceRecord{ID: v.ID, SHA256: sum(raw), Bytes: len(raw), Source: v.Source})
	}
	ids := map[string]bool{}
	for _, v := range x.Edges {
		if !validID(v.ID) || ids[v.ID] || !nodes[v.From] || !nodes[v.To] || !in(v.Kind, "depends_on", "access", "exposes", "mitigates", "observes") || !in(v.State, "observed", "confirmed", "inferred", "hypothesis", "disproven") {
			return x, nil, errors.New("invalid graph edge")
		}
		ids[v.ID] = true
		if len(v.EvidenceIDs) == 0 || len(v.EvidenceIDs) > 16 {
			return x, nil, errors.New("edge evidence is required")
		}
		refs := map[string]bool{}
		for _, id := range v.EvidenceIDs {
			if !ev[id] || refs[id] {
				return x, nil, errors.New("missing/duplicate edge evidence")
			}
			refs[id] = true
		}
		t, e := ts(v.ObservedAt)
		if e != nil || t.After(snap) {
			return x, nil, errors.New("edge timestamp after snapshot")
		}
		if v.VerifiedBy != "" && !validID(v.VerifiedBy) {
			return x, nil, errors.New("invalid verification identifier")
		}
		if v.State == "confirmed" && v.VerifiedBy == "" {
			return x, nil, errors.New("confirmed edge missing human attestation")
		}
		if v.State != "confirmed" && v.VerifiedBy != "" {
			return x, nil, errors.New("verification cannot promote non-confirmed state")
		}
	}
	sort.Slice(x.Nodes, func(i, j int) bool { return x.Nodes[i].ID < x.Nodes[j].ID })
	sort.Slice(x.Edges, func(i, j int) bool { return x.Edges[i].ID < x.Edges[j].ID })
	sort.Strings(x.EntryNodes)
	sort.Strings(x.TargetNodes)
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return x, records, nil
}
func edgesFor(x Input, exclude string, add string) []Edge {
	out := []Edge{}
	for _, v := range x.Edges {
		if v.ID == exclude {
			continue
		}
		if v.State == "confirmed" || v.ID == add {
			if v.Kind != "mitigates" && v.Kind != "observes" {
				out = append(out, v)
			}
		}
	}
	return out
}

// paths computes one shortest confirmed, attested route per entry/target pair.
// The bounded BFS avoids exponential enumeration of cyclic or dense graphs.
func paths(x Input, excl, add string) []Path {
	adjacency := map[string][]Edge{}
	for _, e := range edgesFor(x, excl, add) {
		adjacency[e.From] = append(adjacency[e.From], e)
	}
	out := []Path{}
	targetSet := map[string]bool{}
	for _, t := range x.TargetNodes {
		targetSet[t] = true
	}
	for _, entry := range x.EntryNodes {
		type step struct {
			node string
			ids  []string
		}
		queue := []step{{node: entry, ids: []string{}}}
		visited := map[string]bool{entry: true}
		for len(queue) > 0 {
			w := queue[0]
			queue = queue[1:]
			if targetSet[w.node] && len(w.ids) > 0 {
				out = append(out, Path{From: entry, To: w.node, EdgeIDs: w.ids})
			}
			if len(w.ids) >= maxPathDepth {
				continue
			}
			for _, e := range adjacency[w.node] {
				if visited[e.To] {
					continue
				}
				visited[e.To] = true
				ids := append(append([]string{}, w.ids...), e.ID)
				queue = append(queue, step{node: e.To, ids: ids})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return strings.Join(a.EdgeIDs, "/") < strings.Join(b.EdgeIDs, "/")
	})
	if len(out) > maxPaths {
		return out[:maxPaths]
	}
	return out
}

func targets(ps []Path) map[string]bool {
	out := map[string]bool{}
	for _, p := range ps {
		out[p.To] = true
	}
	return out
}
func Analyze(b []byte) (Result, error) {
	x, recs, e := Validate(b)
	if e != nil {
		return Result{}, e
	}
	r := Result{Schema: ResultSchema, SourceSchema: x.Schema, InputSHA256: sum(b), ScopeID: x.Authorization.ScopeID, Snapshot: x.Snapshot, Nodes: x.Nodes, Evidence: recs, Findings: []Finding{}, AttackPaths: []Path{}, NegativeEvidence: []string{}, Contradictions: [][]string{}, MissingLinks: []string{}, InformationGain: []InfoGain{}, BlastRadius: map[string]int{}, GraphCuts: []Counterfactual{}, Limitations: []string{"Reported human identities are unverified input assertions; signatures are not checked.", "Only one shortest confirmed route per entry/target pair is shown; path depth is limited to eight.", "Information-gain and counterfactual values are bounded graph heuristics, not exploitability evidence.", "ProofGraph never probes or verifies external assets and never upgrades AI inferences to confirmed evidence."}}
	contradictory := map[string][]Edge{}
	for _, v := range x.Edges {
		r.Findings = append(r.Findings, Finding{EdgeID: v.ID, From: v.From, To: v.To, Kind: v.Kind, State: v.State, EvidenceIDs: append([]string{}, v.EvidenceIDs...), HumanAssertion: v.State == "confirmed"})
		key := v.From + "/" + v.To + "/" + v.Kind
		contradictory[key] = append(contradictory[key], v)
		if v.State == "disproven" {
			r.NegativeEvidence = append(r.NegativeEvidence, v.ID)
		}
		if v.State == "hypothesis" || v.State == "inferred" {
			r.MissingLinks = append(r.MissingLinks, v.ID)
		}
	}
	for _, group := range contradictory {
		var pos, neg []string
		for _, v := range group {
			if v.State == "confirmed" {
				pos = append(pos, v.ID)
			}
			if v.State == "disproven" {
				neg = append(neg, v.ID)
			}
		}
		if len(pos) > 0 && len(neg) > 0 {
			ids := append(pos, neg...)
			sort.Strings(ids)
			r.Contradictions = append(r.Contradictions, ids)
		}
	}
	sort.Slice(r.Contradictions, func(i, j int) bool {
		return strings.Join(r.Contradictions[i], "/") < strings.Join(r.Contradictions[j], "/")
	})
	r.AttackPaths = paths(x, "", "")
	baseline := targets(r.AttackPaths)
	for _, entry := range x.EntryNodes {
		sub := x
		sub.EntryNodes = []string{entry}
		r.BlastRadius[entry] = len(targets(paths(sub, "", "")))
	}
	for _, v := range x.Edges {
		if v.State == "confirmed" {
			after := targets(paths(x, v.ID, ""))
			missing := 0
			for t := range baseline {
				if !after[t] {
					missing++
				}
			}
			if missing > 0 {
				r.GraphCuts = append(r.GraphCuts, Counterfactual{RemovedEdge: v.ID, DisconnectedTargets: missing})
			}
		}
		if v.State == "hypothesis" || v.State == "inferred" {
			after := targets(paths(x, "", v.ID))
			added := 0
			for t := range after {
				if !baseline[t] {
					added++
				}
			}
			r.InformationGain = append(r.InformationGain, InfoGain{EdgeID: v.ID, PossibleNewPaths: added})
		}
	}
	sort.Slice(r.GraphCuts, func(i, j int) bool {
		if r.GraphCuts[i].DisconnectedTargets != r.GraphCuts[j].DisconnectedTargets {
			return r.GraphCuts[i].DisconnectedTargets > r.GraphCuts[j].DisconnectedTargets
		}
		return r.GraphCuts[i].RemovedEdge < r.GraphCuts[j].RemovedEdge
	})
	sort.Slice(r.InformationGain, func(i, j int) bool {
		if r.InformationGain[i].PossibleNewPaths != r.InformationGain[j].PossibleNewPaths {
			return r.InformationGain[i].PossibleNewPaths > r.InformationGain[j].PossibleNewPaths
		}
		return r.InformationGain[i].EdgeID < r.InformationGain[j].EdgeID
	})
	r.SHA256 = ""
	stable, _ := json.Marshal(r)
	r.SHA256 = sum(stable)
	return r, nil
}
func Encode(r Result) ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// validateResultShape enforces the value constraints actually published in
// proofgraph.result/v1. A matching (unkeyed) digest alone cannot establish
// schema validity, let alone publisher authenticity.
func validateResultShape(r Result) error {
	if !validID(r.ScopeID) {
		return errors.New("invalid report scope")
	}
	if _, e := ts(r.Snapshot); e != nil {
		return errors.New("invalid report snapshot")
	}
	if !validDigest(r.InputSHA256) {
		return errors.New("invalid input digest")
	}
	if len(r.Nodes) > maxNodes || len(r.Evidence) > maxEvidence || len(r.MissingLinks) > maxEdges || len(r.NegativeEvidence) > maxEdges {
		return errors.New("report resource limit")
	}
	for _, n := range r.Nodes {
		if !validID(n.ID) || !validID(n.ScopeID) || !in(n.Type, "asset", "identity", "service", "control", "finding") {
			return errors.New("invalid report node")
		}
	}
	for _, v := range r.Evidence {
		if !validID(v.ID) || !validDigest(v.SHA256) || v.Bytes < 1 || v.Bytes > MaxRawEvidence {
			return errors.New("invalid report evidence")
		}
	}
	for _, ids := range [][]string{r.MissingLinks, r.NegativeEvidence} {
		for _, id := range ids {
			if !validID(id) {
				return errors.New("invalid report edge reference")
			}
		}
	}
	return validateResultLinks(r)
}

// validateResultLinks checks relationships that cannot be expressed by the
// loosely typed nested arrays in result/v1. It does NOT establish authorship:
// the report's SHA-256 is intentionally unkeyed and can be recomputed.
func validateResultLinks(r Result) error {
	nodes := make(map[string]bool, len(r.Nodes))
	for _, n := range r.Nodes {
		if n.ScopeID != r.ScopeID || nodes[n.ID] {
			return errors.New("cross-scope or duplicate report node")
		}
		nodes[n.ID] = true
	}
	evidence := make(map[string]bool, len(r.Evidence))
	for _, v := range r.Evidence {
		if evidence[v.ID] {
			return errors.New("duplicate report evidence")
		}
		evidence[v.ID] = true
	}
	if len(r.Findings) > maxEdges || len(r.AttackPaths) > maxPaths {
		return errors.New("report graph resource limit")
	}
	findings := make(map[string]Finding, len(r.Findings))
	for _, f := range r.Findings {
		if !validID(f.EdgeID) || !nodes[f.From] || !nodes[f.To] ||
			!in(f.Kind, "depends_on", "access", "exposes", "mitigates", "observes") ||
			!in(f.State, "observed", "confirmed", "inferred", "hypothesis", "disproven") ||
			f.HumanAssertion != (f.State == "confirmed") || len(f.EvidenceIDs) < 1 || len(f.EvidenceIDs) > 16 {
			return errors.New("invalid report finding")
		}
		if _, present := findings[f.EdgeID]; present {
			return errors.New("duplicate report finding")
		}
		refs := map[string]bool{}
		for _, id := range f.EvidenceIDs {
			if !evidence[id] || refs[id] {
				return errors.New("invalid report finding evidence")
			}
			refs[id] = true
		}
		findings[f.EdgeID] = f
	}
	for _, id := range r.NegativeEvidence {
		if f, present := findings[id]; !present || f.State != "disproven" {
			return errors.New("negative evidence references non-disproven edge")
		}
	}
	for _, id := range r.MissingLinks {
		if f, present := findings[id]; !present || !in(f.State, "hypothesis", "inferred") {
			return errors.New("missing link references non-hypothetical edge")
		}
	}
	// The report is still unauthenticated: these checks only prevent an
	// internally fabricated interpretation from receiving a PASS.
	if len(r.Contradictions) > maxEdges || len(r.GraphCuts) > maxEdges ||
		len(r.InformationGain) > maxEdges || len(r.BlastRadius) > 4 {
		return errors.New("derived metric resource limit")
	}
	wantNegative, wantMissing := []string{}, []string{}
	groups := map[string][]Finding{}
	for _, f := range r.Findings {
		switch f.State {
		case "disproven":
			wantNegative = append(wantNegative, f.EdgeID)
		case "hypothesis", "inferred":
			wantMissing = append(wantMissing, f.EdgeID)
		}
		groups[f.From+"/"+f.To+"/"+f.Kind] = append(groups[f.From+"/"+f.To+"/"+f.Kind], f)
	}
	sort.Strings(wantNegative)
	sort.Strings(wantMissing)
	// Analyze emits canonical, complete negative-evidence and missing-link sets.
	if !reflect.DeepEqual(r.NegativeEvidence, wantNegative) ||
		!reflect.DeepEqual(r.MissingLinks, wantMissing) {
		return errors.New("incomplete or fabricated derived evidence sets")
	}
	wantContradictions := [][]string{}
	for _, g := range groups {
		pos, neg := []string{}, []string{}
		for _, f := range g {
			if f.State == "confirmed" {
				pos = append(pos, f.EdgeID)
			}
			if f.State == "disproven" {
				neg = append(neg, f.EdgeID)
			}
		}
		if len(pos) > 0 && len(neg) > 0 {
			ids := append(pos, neg...)
			sort.Strings(ids)
			wantContradictions = append(wantContradictions, ids)
		}
	}
	sort.Slice(wantContradictions, func(i, j int) bool {
		return strings.Join(wantContradictions[i], "/") < strings.Join(wantContradictions[j], "/")
	})
	if !reflect.DeepEqual(r.Contradictions, wantContradictions) {
		return errors.New("fabricated or missing contradiction")
	}
	if len(r.BlastRadius) == 0 {
		return errors.New("missing blast radius")
	}
	for id, value := range r.BlastRadius {
		if !nodes[id] || value < 0 || value > 4 {
			return errors.New("invalid blast radius reference or bound")
		}
	}
	seenGain := map[string]bool{}
	for _, gain := range r.InformationGain {
		f, ok := findings[gain.EdgeID]
		if !ok || !in(f.State, "hypothesis", "inferred") || seenGain[gain.EdgeID] ||
			gain.PossibleNewPaths < 0 || gain.PossibleNewPaths > 4 {
			return errors.New("invalid information gain")
		}
		seenGain[gain.EdgeID] = true
	}
	if len(seenGain) != len(wantMissing) {
		return errors.New("missing information gain entry")
	}
	seenCut := map[string]bool{}
	for _, cut := range r.GraphCuts {
		f, ok := findings[cut.RemovedEdge]
		if !ok || f.State != "confirmed" || in(f.Kind, "mitigates", "observes") ||
			seenCut[cut.RemovedEdge] || cut.DisconnectedTargets < 1 || cut.DisconnectedTargets > 4 {
			return errors.New("invalid graph cut")
		}
		seenCut[cut.RemovedEdge] = true
	}
	for _, p := range r.AttackPaths {
		if !nodes[p.From] || !nodes[p.To] || len(p.EdgeIDs) == 0 || len(p.EdgeIDs) > maxPathDepth {
			return errors.New("invalid report attack path")
		}
		current := p.From
		for _, id := range p.EdgeIDs {
			f, present := findings[id]
			if !present || f.State != "confirmed" || in(f.Kind, "mitigates", "observes") || f.From != current {
				return errors.New("unsupported report attack path")
			}
			current = f.To
		}
		if current != p.To {
			return errors.New("disconnected report attack path")
		}
	}
	for id := range seenCut {
		onReportedPath := false
		for _, p := range r.AttackPaths {
			for _, edgeID := range p.EdgeIDs {
				if edgeID == id {
					onReportedPath = true
				}
			}
		}
		if !onReportedPath {
			return errors.New("graph cut absent from confirmed paths")
		}
	}
	return nil
}

func validDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for i := len("sha256:"); i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func VerifyReport(b []byte) error {
	var r Result
	if e := strictJSON(b, &r); e != nil {
		return e
	}
	if r.Schema != ResultSchema || r.SourceSchema != Schema {
		return errors.New("schema mismatch")
	}
	stored := r.SHA256
	if !validDigest(stored) {
		return errors.New("invalid report digest")
	}
	if e := validateResultShape(r); e != nil {
		return e
	}
	r.SHA256 = ""
	stable, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if sum(stable) != stored {
		return errors.New("report digest mismatch")
	}
	return nil
}
func Replay(input, report []byte) error {
	if e := VerifyReport(report); e != nil {
		return e
	}
	r, e := Analyze(input)
	if e != nil {
		return e
	}
	want, e := Encode(r)
	if e != nil {
		return e
	}
	var stored Result
	if e = strictJSON(report, &stored); e != nil {
		return e
	}
	got, e := Encode(stored)
	if e != nil {
		return e
	}
	if !bytes.Equal(want, got) {
		return errors.New("replay mismatch")
	}
	return nil
}
func Describe() string { return fmt.Sprintf("ProofGraph v0.1.0-rc12 (%s)", Schema) }
