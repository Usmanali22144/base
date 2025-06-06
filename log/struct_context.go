package log

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
)

// StructContextOption defines options for StructContext
type StructContextOption func(*structContext)

// WithPrefix adds a prefix to all struct field names
func WithPrefix(prefix string) StructContextOption {
	return func(sc *structContext) {
		sc.prefix = prefix
	}
}

// WithTag adds a custom tag to look for in struct fields
func WithTag(tag string) StructContextOption {
	return func(sc *structContext) {
		sc.tag = tag
	}
}

// structContext implements the Context interface for struct fields
type structContext struct {
	fields map[string]Valuer
	prefix string
	tag    string
}

// Context returns a map of field names to Valuer implementations
func (sc *structContext) Context() map[string]Valuer {
	return sc.fields
}

// StructContext creates a Context from a struct, extracting fields tagged with `log`
// It supports nested structs and respects omitempty directive
func StructContext(v interface{}, opts ...StructContextOption) Context {
	sc := &structContext{
		fields: make(map[string]Valuer),
		prefix: "",
		tag:    "log",
	}

	// Apply options
	for _, opt := range opts {
		opt(sc)
	}

	if v == nil {
		return sc
	}

	value := reflect.ValueOf(v)
	extractFields(value, sc, "")

	return sc
}

// extractFields recursively extracts fields from a struct value
func extractFields(value reflect.Value, sc *structContext, path string) {
	// If it's a pointer, dereference it
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return
		}
		value = value.Elem()
	}

	// Only process structs
	if value.Kind() != reflect.Struct {
		return
	}

	typ := value.Type()
	for i := range typ.NumField() {
		field := typ.Field(i)
		fieldValue := value.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Get the log tag
		tag := field.Tag.Get(sc.tag)
		if tag == "" {
			// Skip fields without log tag
			continue
		}

		// Parse the tag
		tagParts := strings.Split(tag, ",")
		fieldName := tagParts[0]
		if fieldName == "" {
			fieldName = field.Name
		}

		// Handle omitempty
		omitEmpty := slices.Contains(tagParts, "omitempty")

		// Build the full field name with path and prefix
		fullName := fieldName
		if path != "" {
			fullName = path + "." + fieldName
		}

		// we add prefis only once, for the field on the first level
		if path == "" && sc.prefix != "" {
			fullName = sc.prefix + "." + fullName
		}

		// Check if field should be omitted due to empty value
		if omitEmpty && fieldValue.IsZero() {
			continue
		}

		// Store the field value
		valuer := valueToValuer(fieldValue)
		if valuer != nil {
			sc.fields[fullName] = valuer
		}

		// If it's a struct, recursively extract its fields only if it has a log tag
		if fieldValue.Kind() == reflect.Struct ||
			(fieldValue.Kind() == reflect.Ptr && !fieldValue.IsNil() && fieldValue.Elem().Kind() == reflect.Struct) {
			extractFields(fieldValue, sc, fullName)
		}
	}
}

// valueToValuer converts a reflect.Value to a Valuer
func valueToValuer(v reflect.Value) Valuer {
	if !v.IsValid() {
		return nil
	}

	//nolint:exhaustive
	switch v.Kind() {
	case reflect.Bool:
		return Bool(v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return Int64(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return Uint64(v.Uint())
	case reflect.Float32:
		return Float32(float32(v.Float()))
	case reflect.Float64:
		return Float64(v.Float())
	case reflect.String:
		return String(v.String())
	case reflect.Ptr:
		if v.IsNil() {
			return &any{nil}
		}
		return valueToValuer(v.Elem())
	case reflect.Struct:
		// Check if it's a time.Time
		if v.Type().String() == "time.Time" {
			if v.CanInterface() {
				t, ok := v.Interface().(time.Time)
				if ok {
					return Time(t)
				}
			}
		}
	}

	// Try to use Stringer for complex types
	if v.CanInterface() {
		if stringer, ok := v.Interface().(fmt.Stringer); ok {
			return Stringer(stringer)
		}
	}

	// Return as string representation for other types
	return String(fmt.Sprintf("%v", v.Interface()))
}
