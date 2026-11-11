package lua54

import (
	"context"
	"fmt"
	"strings"

	"github.com/SiriusScan/scribe"
	rt "github.com/SiriusScan/scribe/internal/thirdparty/golua/runtime"
	"github.com/SiriusScan/scribe/internal/thirdparty/golua/scanner"
	"github.com/SiriusScan/scribe/internal/thirdparty/golua/token"
	"io"
)

// Check compiles source and checks literal requires and direct module members.
// It never executes script code. Dynamic module access cannot be certified.
func Check(script scribe.Script) error {
	if script.Dialect != scribe.Sirius && script.Dialect != scribe.NSE {
		return fmt.Errorf("explicit dialect required")
	}
	if len(script.Source) == 0 || len(script.Source) > scribe.MaxSourceBytes {
		return fmt.Errorf("invalid source size")
	}
	vm := rt.New(io.Discard)
	defer vm.Close(nil)
	_, err := vm.MainThread().CallContext(rt.RuntimeContextDef{HardLimits: rt.RuntimeResources{Cpu: 10_000_000, Memory: 32 << 20, Millis: 5000}}, func() error {
		modules := loadLibraries(vm)
		if script.Dialect == scribe.NSE {
			if err := loadNSE(context.Background(), vm, scribe.Task{}, modules); err != nil {
				return err
			}
		} else {
			m := rt.NewTable()
			vm.SetEnv(m, "call", rt.BoolValue(true))
			modules["sirius"] = rt.TableValue(m)
		}
		if _, err := vm.CompileAndLoadLuaChunk(script.ID, script.Source, rt.TableValue(vm.GlobalEnv())); err != nil {
			return err
		}
		scan := scanner.New(script.ID, script.Source)
		var ts []*token.Token
		for {
			t := scan.Scan()
			if t.Type == token.EOF {
				break
			}
			if t.Type == token.INVALID || t.Type == token.UNFINISHED {
				return fmt.Errorf("invalid Lua token")
			}
			ts = append(ts, t)
		}
		aliases := map[string]string{}
		for name := range modules {
			aliases[name] = name
		}
		for i, t := range ts {
			if string(t.Lit) != "require" || t.Type != token.IDENT {
				continue
			}
			j := i + 1
			if j < len(ts) && ts[j].Type == token.SgOpenBkt {
				j++
			}
			if j >= len(ts) || ts[j].Type != token.STRING {
				return fmt.Errorf("dynamic require cannot be checked")
			}
			literal := string(ts[j].Lit)
			name := literal[1 : len(literal)-1]
			if strings.ContainsRune(name, 92) {
				return fmt.Errorf("escaped require literal cannot be checked")
			}
			if _, ok := modules[name]; !ok {
				return fmt.Errorf("unsupported Lua module %q", name)
			}
			if i >= 2 && ts[i-1].Type == token.SgAssign && ts[i-2].Type == token.IDENT {
				aliases[string(ts[i-2].Lit)] = name
			}
		}
		for i := 0; i+2 < len(ts); i++ {
			name, ok := aliases[string(ts[i].Lit)]
			if !ok || ts[i].Type != token.IDENT {
				continue
			}
			if ts[i+1].Type != token.SgDot && ts[i+1].Type != token.SgColon {
				continue
			}
			table, ok := modules[name].TryTable()
			if ok && table.Get(rt.StringValue(string(ts[i+2].Lit))).IsNil() {
				return fmt.Errorf("unsupported API %s.%s", name, ts[i+2].Lit)
			}
		}
		return nil
	})
	return err
}
