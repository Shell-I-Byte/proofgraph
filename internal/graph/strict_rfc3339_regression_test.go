package graph

import (
	"bytes"
	"encoding/json"
	"testing"
)

// RFC 3339 section 5.6 requires a two-digit time-hour, a dot for
// fractional seconds, zone hours 00..23 and zone minutes 00..59.
// time.Parse(time.RFC3339, ...) is deliberately more permissive.
func TestRejectNonRFC3339TimeRepresentations(t *testing.T) {
	controls := []struct{ name, original, malformed string }{
		{"one-digit snapshot hour", `"snapshot":"2026-10-09T06:00:00Z"`, `"snapshot":"2026-10-09T6:00:00Z"`},
		{"comma fractional snapshot", `"snapshot":"2026-10-09T06:00:00Z"`, `"snapshot":"2026-10-09T06:00:00,123Z"`},
		{"zone hour 24 snapshot", `"snapshot":"2026-10-09T06:00:00Z"`, `"snapshot":"2026-10-09T06:00:00+24:00"`},
		{"zone minute 60 snapshot", `"snapshot":"2026-10-09T06:00:00Z"`, `"snapshot":"2026-10-09T06:00:00+00:60"`},
		{"negative zone hour 24 snapshot", `"snapshot":"2026-10-09T06:00:00Z"`, `"snapshot":"2026-10-09T06:00:00-24:00"`},
		{"zone minute 60 authorization start", `"valid_from":"2026-10-01T00:00:00Z"`, `"valid_from":"2026-10-01T00:00:00+01:60"`},
		{"zone hour 24 authorization end", `"valid_until":"2026-10-31T00:00:00Z"`, `"valid_until":"2026-10-31T00:00:00+24:00"`},
		{"one-digit observed hour", `"observed_at":"2026-10-08T00:00:00Z"`, `"observed_at":"2026-10-08T0:00:00Z"`},
		{"comma observed fractional", `"observed_at":"2026-10-08T00:00:00Z"`, `"observed_at":"2026-10-08T00:00:00,123Z"`},
		{"zone minute 60 observed edge", `"observed_at":"2026-10-08T00:00:00Z"`, `"observed_at":"2026-10-08T00:00:00+01:60"`},
	}
	for _, c := range controls {
		t.Run(c.name, func(t *testing.T) {
			bad := bytes.Replace(fixture(), []byte(c.original), []byte(c.malformed), 1)
			if bytes.Equal(bad, fixture()) {
				t.Fatal("test did not change fixture")
			}
			if _, err := Analyze(bad); err == nil {
				t.Fatal("invalid RFC3339 time accepted")
			}
		})
	}
}

func TestAcceptValidRFC3339TimeRepresentations(t *testing.T) {
	controls := []struct{ name, from, to string }{
		{"canonical Z", `"snapshot":"2026-10-09T06:00:00Z"`, `"snapshot":"2026-10-09T06:00:00Z"`},
		{"dot fractional", `"snapshot":"2026-10-09T06:00:00Z"`, `"snapshot":"2026-10-09T06:00:00.123Z"`},
		{"positive offset", `"snapshot":"2026-10-09T06:00:00Z"`, `"snapshot":"2026-10-09T06:00:00+01:30"`},
		{"negative offset", `"snapshot":"2026-10-09T06:00:00Z"`, `"snapshot":"2026-10-09T06:00:00-01:30"`},
		{"maximum representable offset", `"snapshot":"2026-10-09T06:00:00Z"`, `"snapshot":"2026-10-09T06:00:00+23:59"`},
	}
	for _, c := range controls {
		t.Run(c.name, func(t *testing.T) {
			input := bytes.Replace(fixture(), []byte(c.from), []byte(c.to), 1)
			if _, err := Analyze(input); err != nil {
				t.Fatalf("valid RFC3339 rejected: %v", err)
			}
		})
	}
}

// An untrusted report writer can recompute the unkeyed SHA-256. A bad
// timestamp must fail independently of its self-consistent digest.
func TestRejectSelfRehashedReportWithNonRFC3339Snapshot(t *testing.T) {
	for _, timestamp := range []string{
		"2026-10-09T6:00:00Z",
		"2026-10-09T06:00:00,123Z",
		"2026-10-09T06:00:00+24:00",
		"2026-10-09T06:00:00+00:60",
	} {
		t.Run(timestamp, func(t *testing.T) {
			result, err := Analyze(fixture())
			if err != nil {
				t.Fatal(err)
			}
			result.Snapshot = timestamp
			result.SHA256 = ""
			compact, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			result.SHA256 = sum(compact)
			serialized, err := Encode(result)
			if err != nil {
				t.Fatal(err)
			}
			if err = VerifyReport(serialized); err == nil {
				t.Fatal("self-rehashed malformed report accepted")
			}
		})
	}
}
