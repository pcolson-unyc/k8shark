package hub

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pablocolson/k8shark/pkg/api"
)

// Distinct numeric values catch accessors accidentally reading a neighboring
// field. Allocated zero-valued subobjects exercise missing-value sentinels.
func numericFixture(populated bool) *api.Entry {
	e := &api.Entry{}
	seed := int64(100)
	var fill func(reflect.Value)
	fill = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.Pointer:
			if v.Type().Elem().Kind() == reflect.Struct {
				v.Set(reflect.New(v.Type().Elem()))
				fill(v.Elem())
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Field(i).CanSet() {
					fill(v.Field(i))
				}
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if populated {
				seed++
				v.SetInt(seed)
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if populated {
				seed++
				v.SetUint(uint64(seed))
			}
		case reflect.Float32, reflect.Float64:
			if populated {
				seed++
				v.SetFloat(float64(seed) + 0.25)
			}
		}
	}
	fill(reflect.ValueOf(e).Elem())
	return e
}

func TestNumericPredicatesMatchLegacyGetters(t *testing.T) {
	fields := []string{"elapsed", "latency", "http.status", "status.code", "statuscode", "size", "rowcount", "deliverytag", "src.port", "dst.port"}
	for _, f := range fieldCatalog {
		fields = append(fields, f.Name)
	}
	fixtures := []*api.Entry{{}, numericFixture(false), numericFixture(true)}
	for _, field := range fields {
		if numericFieldGetter(field) == nil || fieldGetter(field) == nil {
			continue
		}
		for _, op := range []string{">", "<", ">=", "<=", "==", "!=", "contains"} {
			for _, literal := range []string{"-1", "0", "1", "200", "500", "1e20"} {
				legacy, err := valueMatcher(field, op, literal)
				if err != nil {
					t.Fatal(err)
				}
				pred, err := CompileFilter(strings.ToUpper(field) + " " + op + " " + literal)
				if err != nil {
					t.Fatal(err)
				}
				for i, e := range fixtures {
					want := legacy(fieldGetter(field)(e))
					if got := pred(e); got != want {
						t.Errorf("%s %s %s fixture %d: got %v, legacy %v", field, op, literal, i, got, want)
					}
				}
			}
		}
	}
	for _, field := range []string{"request.body", "http.host"} {
		e := &api.Entry{Request: api.Payload{Body: "12.5", Host: "12.5"}}
		pred, err := CompileFilter(field + " > 12")
		if err != nil || !pred(e) {
			t.Fatalf("numeric string fallback %s: %v", field, err)
		}
	}
}
