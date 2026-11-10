package lua54

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/SiriusScan/scribe"
	rt "github.com/SiriusScan/scribe/internal/thirdparty/golua/runtime"
)

// Conversion limits also bound Go allocations outside the VM's accounting.
const (
	MaxOutputBytes = 1 << 20
	MaxValueNodes  = 10_000
	MaxValueDepth  = 32
	MaxFindings    = 256
)

type conversion struct {
	ctx          context.Context
	vm           *rt.Runtime
	bytes, nodes int
	visiting     map[*rt.Table]bool
}

func newConversion(ctx context.Context, vm *rt.Runtime) *conversion {
	return &conversion{ctx: ctx, vm: vm, visiting: make(map[*rt.Table]bool)}
}

func (c *conversion) account(size, depth int) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if depth > MaxValueDepth {
		return errors.New("cyclic or excessively nested value (maximum depth 32)")
	}
	c.nodes++
	c.bytes += size
	if c.nodes > MaxValueNodes || c.bytes > MaxOutputBytes {
		return errors.New("value exceeds conversion limit (1 MiB or 10000 nodes)")
	}
	c.vm.RequireCPU(uint64(1 + size/32))
	c.vm.RequireMem(uint64(size + 32))
	return nil
}

func (c *conversion) string(value string, depth int) error {
	if !utf8.ValidString(value) {
		return errors.New("JSON data must contain valid UTF-8 strings")
	}
	return c.account(len(value), depth)
}

func (c *conversion) fromLua(value rt.Value, depth int) (any, error) {
	if err := c.account(0, depth); err != nil {
		return nil, err
	}
	switch value.Type() {
	case rt.NilType:
		return nil, nil
	case rt.BoolType:
		return value.AsBool(), nil
	case rt.IntType:
		return value.AsInt(), nil
	case rt.FloatType:
		f := value.AsFloat()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, errors.New("nonfinite numbers are not JSON data")
		}
		return f, nil
	case rt.StringType:
		s := value.AsString()
		return s, c.string(s, depth)
	case rt.TableType:
		table := value.AsTable()
		if c.visiting[table] {
			return nil, errors.New("cyclic Lua table")
		}
		c.visiting[table] = true
		defer delete(c.visiting, table)
		object := make(map[string]any)
		array := make(map[int64]any)
		var key rt.Value
		for {
			next, entry, ok := table.Next(key)
			if !ok || next.IsNil() {
				break
			}
			key = next
			converted, err := c.fromLua(entry, depth+1)
			if err != nil {
				return nil, err
			}
			if name, ok := key.TryString(); ok {
				if err := c.string(name, depth+1); err != nil {
					return nil, err
				}
				object[name] = converted
			} else if index, ok := key.TryInt(); ok && index > 0 && index <= MaxValueNodes {
				array[index] = converted
			} else {
				return nil, errors.New("Lua table keys must be strings or contiguous positive integers")
			}
		}
		if len(object) > 0 && len(array) > 0 {
			return nil, errors.New("mixed object and array table keys are unsupported")
		}
		if len(array) == 0 {
			return object, nil
		}
		values := make([]any, len(array))
		for i := range values {
			entry, ok := array[int64(i+1)]
			if !ok {
				return nil, errors.New("Lua arrays must have contiguous positive integer keys")
			}
			values[i] = entry
		}
		return values, nil
	default:
		return nil, fmt.Errorf("Lua %s values cannot be returned as JSON data", value.TypeName())
	}
}

// toLua accepts explicit JSON-compatible Go values without reflection or
// dynamic imports. Maps and slices are bounded recursively, including cycles.
func (c *conversion) toLua(value any, depth int) (rt.Value, error) {
	if err := c.account(0, depth); err != nil {
		return rt.NilValue, err
	}
	switch v := value.(type) {
	case nil:
		return rt.NilValue, nil
	case bool:
		return rt.BoolValue(v), nil
	case string:
		if err := c.string(v, depth); err != nil {
			return rt.NilValue, err
		}
		return rt.StringValue(v), nil
	case int:
		return rt.IntValue(int64(v)), nil
	case int8:
		return rt.IntValue(int64(v)), nil
	case int16:
		return rt.IntValue(int64(v)), nil
	case int32:
		return rt.IntValue(int64(v)), nil
	case int64:
		return rt.IntValue(v), nil
	case uint:
		return c.unsigned(uint64(v))
	case uint8:
		return c.unsigned(uint64(v))
	case uint16:
		return c.unsigned(uint64(v))
	case uint32:
		return c.unsigned(uint64(v))
	case uint64:
		return c.unsigned(v)
	case float32:
		return c.floating(float64(v))
	case float64:
		return c.floating(v)
	case json.Number:
		if integer, err := v.Int64(); err == nil {
			return rt.IntValue(integer), nil
		}
		floating, err := v.Float64()
		if err != nil {
			return rt.NilValue, err
		}
		return c.floating(floating)
	case map[string]any:
		table := rt.NewTable()
		for key, item := range v {
			if err := c.string(key, depth+1); err != nil {
				return rt.NilValue, err
			}
			entry, err := c.toLua(item, depth+1)
			if err != nil {
				return rt.NilValue, err
			}
			c.vm.SetEnv(table, key, entry)
		}
		return rt.TableValue(table), nil
	case map[string]string:
		table := rt.NewTable()
		for key, item := range v {
			if err := c.string(key, depth+1); err != nil {
				return rt.NilValue, err
			}
			entry, err := c.toLua(item, depth+1)
			if err != nil {
				return rt.NilValue, err
			}
			c.vm.SetEnv(table, key, entry)
		}
		return rt.TableValue(table), nil
	case []any:
		table := rt.NewTable()
		for index, item := range v {
			entry, err := c.toLua(item, depth+1)
			if err != nil {
				return rt.NilValue, err
			}
			if entry.IsNil() {
				return rt.NilValue, errors.New("nil array entries cannot be represented in Lua")
			}
			c.vm.SetTable(table, rt.IntValue(int64(index+1)), entry)
		}
		return rt.TableValue(table), nil
	case []string:
		table := rt.NewTable()
		for index, item := range v {
			entry, err := c.toLua(item, depth+1)
			if err != nil {
				return rt.NilValue, err
			}
			c.vm.SetTable(table, rt.IntValue(int64(index+1)), entry)
		}
		return rt.TableValue(table), nil
	default:
		return rt.NilValue, fmt.Errorf("unsupported Go value type %T; use JSON-compatible maps, slices, and scalars", value)
	}
}

func (c *conversion) unsigned(v uint64) (rt.Value, error) {
	if v > math.MaxInt64 {
		return rt.NilValue, errors.New("unsigned integer exceeds Lua integer range")
	}
	return rt.IntValue(int64(v)), nil
}

func (c *conversion) floating(v float64) (rt.Value, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return rt.NilValue, errors.New("nonfinite numbers are not JSON data")
	}
	return rt.FloatValue(v), nil
}

func nativeOutput(ctx context.Context, vm *rt.Runtime, value rt.Value) (scribe.Output, error) {
	converted, err := newConversion(ctx, vm).fromLua(value, 0)
	if err != nil {
		return scribe.Output{}, err
	}
	object, ok := converted.(map[string]any)
	if !ok {
		return scribe.Output{}, errors.New("Sirius action must return an output table")
	}
	for key := range object {
		if key != "data" && key != "findings" {
			return scribe.Output{}, fmt.Errorf("unknown output field %q", key)
		}
	}
	output := scribe.Output{Data: object["data"]}
	if raw, exists := object["findings"]; exists {
		findings, ok := arrayValue(raw)
		if !ok || len(findings) > MaxFindings {
			return scribe.Output{}, errors.New("findings must be an array with at most 256 entries")
		}
		seen := make(map[string]bool)
		for _, item := range findings {
			finding, err := parseFinding(item)
			if err != nil {
				return scribe.Output{}, err
			}
			if seen[finding.ID] {
				return scribe.Output{}, fmt.Errorf("duplicate finding ID %q", finding.ID)
			}
			seen[finding.ID] = true
			output.Findings = append(output.Findings, finding)
		}
	}
	return output, checkOutputSize(output)
}

func arrayValue(value any) ([]any, bool) {
	if items, ok := value.([]any); ok {
		return items, true
	}
	// An empty Lua table has no intrinsic object/array distinction.
	if object, ok := value.(map[string]any); ok && len(object) == 0 {
		return []any{}, true
	}
	return nil, false
}

func parseFinding(value any) (scribe.Finding, error) {
	var finding scribe.Finding
	object, ok := value.(map[string]any)
	if !ok {
		return finding, errors.New("each finding must be an object")
	}
	for key := range object {
		switch key {
		case "id", "title", "severity", "evidence", "references", "metadata":
		default:
			return finding, fmt.Errorf("unknown finding field %q", key)
		}
	}
	var valid bool
	if finding.ID, valid = object["id"].(string); !valid || finding.ID == "" {
		return finding, errors.New("finding id must be a nonempty string")
	}
	if finding.Title, valid = object["title"].(string); !valid || finding.Title == "" {
		return finding, errors.New("finding title must be a nonempty string")
	}
	if finding.Severity, valid = object["severity"].(string); !valid {
		return finding, errors.New("finding severity is required")
	}
	switch finding.Severity {
	case "unknown", "info", "low", "medium", "high", "critical":
	default:
		return finding, errors.New("finding severity must be unknown, info, low, medium, high, or critical")
	}
	if evidence, exists := object["evidence"]; exists {
		if finding.Evidence, valid = evidence.(string); !valid {
			return finding, errors.New("finding evidence must be a string")
		}
	}
	if references, exists := object["references"]; exists {
		items, ok := arrayValue(references)
		if !ok || len(items) > 64 {
			return finding, errors.New("finding references must be an array with at most 64 strings")
		}
		for _, item := range items {
			reference, ok := item.(string)
			if !ok {
				return finding, errors.New("finding references must be strings")
			}
			finding.References = append(finding.References, reference)
		}
	}
	if metadata, exists := object["metadata"]; exists {
		if finding.Metadata, valid = metadata.(map[string]any); !valid {
			return finding, errors.New("finding metadata must be an object")
		}
	}
	return finding, nil
}

func checkOutputSize(output scribe.Output) error {
	data, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("encode output: %w", err)
	}
	if len(data) > MaxOutputBytes {
		return errors.New("encoded output exceeds 1 MiB")
	}
	return nil
}
