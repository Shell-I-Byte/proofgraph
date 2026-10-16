package graph

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

// exactJSONNames rejects case variants that encoding/json v1 would otherwise
// match to a struct field. Duplicate names and malformed JSON are checked
// independently before this function is called.
func exactJSONNames(raw []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	// The published v1 JSON schemas have no nullable members. encoding/json
	// v1 silently maps null onto zero-valued strings, booleans and slices.
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("null JSON member is not permitted")
	}
	switch typ.Kind() {
	case reflect.Struct:
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("null JSON object")
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			return errors.New("invalid JSON object")
		}
		// The Security IR schema permits verified_by *only* on confirmed
		// edges. Checking just the decoded string incorrectly treats an
		// explicitly present empty value as an absent property.
		if typ == reflect.TypeOf(Edge{}) {
			if _, present := members["verified_by"]; present {
				var state string
				if err := json.Unmarshal(members["state"], &state); err != nil || state != "confirmed" {
					return errors.New("verification property requires confirmed state")
				}
			}
		}
		expected := make(map[string]reflect.Type, typ.NumField())
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			key := strings.Split(field.Tag.Get("json"), ",")[0]
			if key == "-" {
				continue
			}
			if key == "" {
				key = field.Name
			}
			expected[key] = field.Type
		}
		// The versioned IR and result schemas require every declared property
		// on these shapes (except Edge.verified_by, which is conditional).
		// Go's encoding/json leaves absent fields at zero values. That makes
		// an omitted required [] or map indistinguishable from null after
		// unmarshalling, and permits a self-rehashed incomplete report.
		// Do not impose stricter rules on output nested shapes for which the
		// published result schema defines no required-property constraints.
		if requiresAllMembers(typ) {
			for name := range expected {
				if typ == reflect.TypeOf(Edge{}) && name == "verified_by" {
					continue
				}
				if _, present := members[name]; !present {
					return errors.New("missing required JSON member")
				}
			}
		}
		for name, value := range members {
			fieldType, ok := expected[name]
			if !ok {
				// Do not echo attacker-controlled member names into stderr.
				return errors.New("unknown or case-variant JSON member")
			}
			if err := exactJSONNames(value, fieldType); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var elements []json.RawMessage
		if err := json.Unmarshal(raw, &elements); err != nil {
			return errors.New("invalid JSON array")
		}
		for _, value := range elements {
			if err := exactJSONNames(value, typ.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			return errors.New("invalid JSON map")
		}
		for _, value := range members {
			if err := exactJSONNames(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

// requiresAllMembers lists the structs whose every non-conditional member
// is required by the published v1 schemas. Keeping this explicit avoids
// silently tightening the less-constrained nested result-array contracts.
func requiresAllMembers(t reflect.Type) bool {
	switch t {
	case reflect.TypeOf(Input{}), reflect.TypeOf(Authorization{}),
		reflect.TypeOf(Node{}), reflect.TypeOf(Evidence{}),
		reflect.TypeOf(Edge{}), reflect.TypeOf(Result{}),
		reflect.TypeOf(EvidenceRecord{}):
		return true
	default:
		return false
	}
}
