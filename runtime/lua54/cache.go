package lua54

import (
	"crypto/sha256"
	"sync"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/internal/thirdparty/golua/code"
	rt "github.com/SiriusScan/scribe/internal/thirdparty/golua/runtime"
)

type programKey struct {
	digest [32]byte
	id     string
}
type program struct {
	key    programKey
	plan   *scribe.Index
	code   *rt.Code
	cost   uint64
	memory uint64
}
type programCache struct {
	mu            sync.Mutex
	entries       int
	ceiling, used uint64
	items         []program // bounded FIFO, immutable templates; no invocation state
}

func (r *runtime) plan(s scribe.Script) (*scribe.Index, programKey, error) {
	key := programKey{sha256.Sum256(s.Source), s.ID}
	c := &r.cache
	c.mu.Lock()
	for _, p := range c.items {
		if p.key == key {
			c.mu.Unlock()
			return p.plan, key, nil
		}
	}
	c.mu.Unlock()
	idx, err := scribe.NewIndex([]scribe.Script{{ID: s.ID, Dialect: s.Dialect, Source: s.Source}})
	if err == nil {
		c.put(program{key: key, plan: idx, cost: uint64(len(s.Source))*2 + uint64(len(s.ID)) + 256})
	}
	return idx, key, err
}
func (c *programCache) put(p program) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries < 0 || p.cost > c.ceiling {
		return
	}
	for i, old := range c.items {
		if old.key == p.key {
			if p.code == nil || old.code != nil {
				return
			}
			c.used -= old.cost
			copy(c.items[i:], c.items[i+1:])
			c.items[len(c.items)-1] = program{}
			c.items = c.items[:len(c.items)-1]
			break
		}
	}
	for len(c.items) > 0 && (len(c.items) >= c.entries || c.used+p.cost > c.ceiling) {
		c.used -= c.items[0].cost
		copy(c.items, c.items[1:])
		c.items[len(c.items)-1] = program{}
		c.items = c.items[:len(c.items)-1]
	}
	c.items = append(c.items, p)
	c.used += p.cost
}
func (r *runtime) load(vm *rt.Runtime, s scribe.Script, key programKey) (*rt.Closure, error) {
	c := &r.cache
	c.mu.Lock()
	var hit program
	for _, p := range c.items {
		if p.key == key {
			hit = p
			break
		}
	}
	c.mu.Unlock()
	if hit.code != nil {
		vm.RequireMem(hit.memory)
		return vm.BindCode(hit.code, rt.TableValue(vm.GlobalEnv())), nil
	}
	unit, size, err := vm.CompileLuaChunk(s.ID, s.Source)
	defer vm.ReleaseMem(size)
	if err != nil {
		return nil, err
	}
	closure := vm.LoadLuaUnit(unit, rt.TableValue(vm.GlobalEnv()))
	// Conservative retained-code accounting covers source, constants, opcodes,
	// VM Code wrappers and selection metadata; oversized entries are not cached.
	memory := uint64(len(unit.Code))*8 + uint64(len(unit.Lines))*4 + uint64(len(unit.Constants))*32
	for _, constant := range unit.Constants {
		switch k := constant.(type) {
		case code.String:
			memory += uint64(len(k))
		case code.Code:
			memory += 256 + uint64(len(k.Name))
			for _, name := range k.UpNames {
				memory += uint64(len(name)) + 16
			}
		}
	}
	cost := size*8 + uint64(len(s.Source))*2 + uint64(len(s.ID)) + 1024
	if hit.plan != nil {
		c.put(program{key: key, plan: hit.plan, code: closure.Code, cost: cost, memory: memory})
	}
	return closure, nil
}
