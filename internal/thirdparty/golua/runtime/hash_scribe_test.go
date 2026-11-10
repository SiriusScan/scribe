// Copyright (c) 2026 Sirius Scan.
// Licensed under the Apache License, Version 2.0; see ../LICENSE.
package runtime

import (
	"io"
	"math"
	"strings"
	"testing"
)

func TestScribeHashEqualValues(t *testing.T) {
	code := &Code{}
	cell := newCell(IntValue(42))
	closureA := &Closure{Code: code, Upvalues: []Cell{cell}}
	closureB := &Closure{Code: code, Upvalues: []Cell{cell}}
	object := NewTable()
	for _, pair := range [][2]Value{
		{NilValue, NilValue},
		{IntValue(0), IntValue(0)},
		{IntValue(math.MinInt64), IntValue(math.MinInt64)},
		{IntValue(math.MaxInt64), IntValue(math.MaxInt64)},
		{FloatValue(0), FloatValue(math.Copysign(0, -1))},
		{FloatValue(-1.25), FloatValue(-1.25)},
		{FloatValue(math.Inf(1)), FloatValue(math.Inf(1))},
		{BoolValue(true), BoolValue(true)},
		{BoolValue(false), BoolValue(false)},
		{StringValue(""), StringValue("")},
		{StringValue("abc"), StringValue(strings.Clone("abc"))},
		{StringValue("long string key"), StringValue(strings.Clone("long string key"))},
		{TableValue(object), TableValue(object)},
		{FunctionValue(closureA), FunctionValue(closureB)},
	} {
		if !pair[0].Equals(pair[1]) {
			t.Fatalf("fixture pair is not equal: %#v %#v", pair[0], pair[1])
		}
		for range 20 {
			if pair[0].Hash() != pair[1].Hash() {
				t.Fatalf("equal values have different hashes: %#v %#v", pair[0], pair[1])
			}
		}
	}
}

func TestScribeComparableInterfaceHash(t *testing.T) {
	type key struct {
		Name string
		ID   int64
	}
	pointer := new(int)
	for _, value := range []any{nil, int64(0), uint64(math.MaxUint64), true, "text", key{"item", 42}, pointer} {
		first := goRuntimeEfaceHash(value, 0)
		for range 20 {
			if got := goRuntimeEfaceHash(value, 0); got != first {
				t.Fatalf("hash changed for comparable interface %#v: %d != %d", value, got, first)
			}
		}
	}
	if goRuntimeEfaceHash(float64(0), 0) != goRuntimeEfaceHash(math.Copysign(0, -1), 0) {
		t.Fatal("comparable interface hashing must preserve float zero equality")
	}
	for _, scalar := range []uint64{0, 1, 1 << 63, math.MaxUint64} {
		first := goRuntimeInt64Hash(scalar, 0)
		if goRuntimeInt64Hash(scalar, 0) != first {
			t.Fatalf("scalar hash changed for %d", scalar)
		}
	}
}

func TestScribeLuaTableKeys(t *testing.T) {
	r := New(io.Discard)
	defer r.Close(nil)
	chunk, err := r.CompileAndLoadLuaChunk("hash-keys", []byte(`
local t = {}
for i = -300, 300 do t[i] = i + 1000 end
for i = -300, 300 do if t[i + 0.0] ~= i + 1000 then return false end end
local zero = -0.0
t[zero] = "zero"
if t[0] ~= "zero" or t[0.0] ~= "zero" then return false end
t[1.25], t[-1.25] = "positive", "negative"
t[true], t[false] = "yes", "no"
t["short"], t["a much longer string key"] = "short", "long"
local key = {}
t[key] = "table"
local function make() return function() return 1 end end
local f = make()
t[f] = "function"
return t[1.25] == "positive" and t[-1.25] == "negative"
  and t[true] == "yes" and t[false] == "no"
  and t["short"] == "short" and t["a much longer string key"] == "long"
  and t[key] == "table" and t[f] == "function"
`), TableValue(r.GlobalEnv()))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Call1(r.MainThread(), FunctionValue(chunk))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equals(BoolValue(true)) {
		t.Fatalf("Lua table key lookup failed: %#v", result)
	}
}
