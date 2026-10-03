package agentapi

import (
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const specPath = "../../api/openapi.yaml"

// openAPISchema is the subset of an OpenAPI schema object the test compares.
type openAPISchema struct {
	Required   []string                  `yaml:"required"`
	Properties map[string]*openAPISchema `yaml:"properties"`
}

type openAPIDocument struct {
	Paths      map[string]map[string]any `yaml:"paths"`
	Components struct {
		Schemas map[string]*openAPISchema `yaml:"schemas"`
	} `yaml:"components"`
}

func loadSpec(t *testing.T) *openAPIDocument {
	t.Helper()

	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}

	var document openAPIDocument
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	return &document
}

// TestOpenAPIPathsMatchRoutes keeps the documented operations in line with
// the routes the agent serves in internal/direct.
func TestOpenAPIPathsMatchRoutes(t *testing.T) {
	want := []string{
		"POST " + PairingPath,
		"GET " + PairingPath + "/{pairing_id}",
		"GET " + NodePath,
		"GET " + SpecificationsPath,
		"GET " + NetworkPath,
		"GET " + DevicesPath,
		"DELETE " + DevicesPath + "/{device_id}",
	}

	var got []string
	for path, operations := range loadSpec(t).Paths {
		for method := range operations {
			got = append(got, strings.ToUpper(method)+" "+path)
		}
	}

	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("documented operations = %v, want %v", got, want)
	}
}

// TestOpenAPISchemasMatchTypes keeps every documented schema in line with the
// JSON fields of its Go type: the same property names, and required exactly
// when the field has no omitempty.
func TestOpenAPISchemasMatchTypes(t *testing.T) {
	types := map[string]any{
		"Error":          Error{},
		"PairingRequest": PairingRequest{},
		"PairingStarted": PairingStarted{},
		"PairingStatus":  PairingStatus{},
		"Node":           Node{},
		"Specifications": Specifications{},
		"Network":        Network{},
		"Device":         Device{},
		"DeviceList":     DeviceList{},
	}

	schemas := loadSpec(t).Components.Schemas
	if got, want := slices.Sorted(maps.Keys(schemas)), slices.Sorted(maps.Keys(types)); !slices.Equal(got, want) {
		t.Fatalf("documented schemas = %v, want %v", got, want)
	}

	for name, value := range types {
		compareSchema(t, name, schemas[name], reflect.TypeOf(value))
	}
}

func compareSchema(t *testing.T, name string, schema *openAPISchema, goType reflect.Type) {
	t.Helper()

	var properties, required []string
	fields := make(map[string]reflect.Type)
	for field := range goType.Fields() {
		tag, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		properties = append(properties, tag)
		fields[tag] = field.Type
		if !strings.Contains(options, "omitempty") && !strings.Contains(options, "omitzero") {
			required = append(required, tag)
		}
	}

	if got := slices.Sorted(maps.Keys(schema.Properties)); !slices.Equal(got, slices.Sorted(slices.Values(properties))) {
		t.Errorf("%s properties = %v, Go fields = %v", name, got, properties)
	}
	if got := slices.Sorted(slices.Values(schema.Required)); !slices.Equal(got, slices.Sorted(slices.Values(required))) {
		t.Errorf("%s required = %v, Go fields without omitempty = %v", name, got, required)
	}

	// Inline objects describe nested agentapi structs; protocol snapshots
	// are documented by reference to internal/protocol instead.
	for property, nested := range schema.Properties {
		fieldType := fields[property]
		if nested == nil || len(nested.Properties) == 0 || fieldType == nil ||
			fieldType.Kind() != reflect.Struct || fieldType == reflect.TypeFor[time.Time]() {
			continue
		}

		compareSchema(t, name+"."+property, nested, fieldType)
	}
}
