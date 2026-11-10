package lua54

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/SiriusScan/scribe"
	rt "github.com/SiriusScan/scribe/internal/thirdparty/golua/runtime"
)

func loadNSE(ctx context.Context, vm *rt.Runtime, task scribe.Task, modules map[string]rt.Value) error {
	args, err := newConversion(ctx, vm).toLua(task.Script.Args, 0)
	if err != nil {
		return fmt.Errorf("script args: %w", err)
	}
	if args.IsNil() {
		args = rt.TableValue(rt.NewTable())
	}
	stdnse := rt.NewTable()
	setFunction(vm, stdnse, "get_script_args", func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
		name, err := c.StringArg(0)
		if err != nil {
			return nil, err
		}
		return c.PushingNext1(t.Runtime, args.AsTable().Get(rt.StringValue(name))), nil
	}, 1, false)
	setFunction(vm, stdnse, "output_table", func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
		return c.PushingNext1(t.Runtime, rt.TableValue(rt.NewTable())), nil
	}, 0, false)
	strictModule(vm, "stdnse", stdnse)
	modules["stdnse"] = rt.TableValue(stdnse)
	shortport := rt.NewTable()
	setFunction(vm, shortport, "portnumber", shortportFactory("number"), 3, false)
	setFunction(vm, shortport, "service", shortportFactory("service"), 3, false)
	setFunction(vm, shortport, "port_or_service", shortportFactory("either"), 4, false)
	strictModule(vm, "shortport", shortport)
	modules["shortport"] = rt.TableValue(shortport)
	vm.SetEnv(vm.GlobalEnv(), "SCRIPT_NAME", rt.StringValue(strings.TrimSuffix(task.Script.ID, ".nse")))
	// This identifies supplied source, not an accessible filesystem path.
	vm.SetEnv(vm.GlobalEnv(), "SCRIPT_PATH", rt.StringValue(task.Script.ID))
	return nil
}

func strictModule(vm *rt.Runtime, name string, module *rt.Table) {
	meta := rt.NewTable()
	setFunction(vm, meta, "__index", func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
		key, _ := c.Arg(1).ToString()
		return nil, fmt.Errorf("unsupported NSE API %s.%s", name, key)
	}, 2, false)
	module.SetMetatable(meta)
}

func shortportFactory(kind string) rt.GoFunctionFunc {
	return func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
		var numbers map[int64]bool
		var services map[string]bool
		var err error
		protoIndex := 1
		if kind != "service" {
			numbers, err = numberSet(t.Runtime, c.Arg(0))
			if err != nil {
				return nil, err
			}
		}
		if kind != "number" {
			serviceIndex := 0
			if kind == "either" {
				serviceIndex = 1
				protoIndex = 2
			}
			services, err = stringSet(t.Runtime, c.Arg(serviceIndex), nil)
			if err != nil {
				return nil, err
			}
		}
		protocols, err := stringSet(t.Runtime, c.Arg(protoIndex), []string{"tcp"})
		if err != nil {
			return nil, err
		}
		for protocol := range protocols {
			if protocol != "tcp" && protocol != "udp" {
				return nil, errors.New("shortport protocol must be tcp or udp")
			}
		}
		states, err := stringSet(t.Runtime, c.Arg(protoIndex+1), []string{"open", "open|filtered"})
		if err != nil {
			return nil, err
		}
		t.RequireMem(128)
		rule := rt.NewGoFunction(func(t *rt.Thread, call *rt.GoCont) (rt.Cont, error) {
			port, err := call.TableArg(1)
			if err != nil {
				return nil, err
			}
			protocol, _ := port.Get(rt.StringValue("protocol")).TryString()
			state, _ := port.Get(rt.StringValue("state")).TryString()
			number, _ := port.Get(rt.StringValue("number")).TryInt()
			service, _ := port.Get(rt.StringValue("service")).TryString()
			matches := protocols[protocol] && states[state] && (numbers[number] || services[service])
			return call.PushingNext1(t.Runtime, rt.BoolValue(matches)), nil
		}, "shortport rule", 2, false)
		rule.SolemnlyDeclareCompliance(compliance)
		return c.PushingNext1(t.Runtime, rt.FunctionValue(rule)), nil
	}
}

func numberSet(vm *rt.Runtime, value rt.Value) (map[int64]bool, error) {
	result := make(map[int64]bool)
	if value.IsNil() {
		return result, nil
	}
	err := eachValue(vm, value, func(value rt.Value) error {
		number, ok := value.TryInt()
		if !ok || number < 1 || number > 65535 {
			return errors.New("shortport numbers must be integers between 1 and 65535")
		}
		result[number] = true
		return nil
	})
	return result, err
}

func stringSet(vm *rt.Runtime, value rt.Value, defaults []string) (map[string]bool, error) {
	result := make(map[string]bool)
	if value.IsNil() {
		for _, entry := range defaults {
			result[entry] = true
		}
		return result, nil
	}
	err := eachValue(vm, value, func(value rt.Value) error {
		entry, ok := value.TryString()
		if !ok {
			return errors.New("shortport lists must contain strings")
		}
		result[entry] = true
		return nil
	})
	return result, err
}

func eachValue(vm *rt.Runtime, value rt.Value, visit func(rt.Value) error) error {
	if table, ok := value.TryTable(); ok {
		var key rt.Value
		count := 0
		length := table.Len()
		for {
			next, item, ok := table.Next(key)
			if !ok || next.IsNil() {
				if int64(count) != length {
					return errors.New("shortport lists must use contiguous integer keys")
				}
				return nil
			}
			count++
			if count > MaxValueNodes {
				return errors.New("shortport list exceeds 10000 entries")
			}
			key = next
			if index, ok := key.TryInt(); !ok || index < 1 || index > length {
				return errors.New("shortport lists must use contiguous integer keys")
			}
			vm.RequireCPU(1)
			vm.RequireMem(64)
			if err := visit(item); err != nil {
				return err
			}
		}
	}
	return visit(value)
}

func runNSE(ctx context.Context, vm *rt.Runtime, task scribe.Task) (scribe.Output, error) {
	env := vm.GlobalEnv()
	for _, phase := range []string{"prerule", "postrule"} {
		if !env.Get(rt.StringValue(phase)).IsNil() {
			return scribe.Output{}, fmt.Errorf("NSE %s is unsupported in this experimental profile", phase)
		}
	}
	if dependencies := env.Get(rt.StringValue("dependencies")); !dependencies.IsNil() {
		table, ok := dependencies.TryTable()
		if !ok {
			return scribe.Output{}, errors.New("NSE dependencies must be a table")
		}
		if key, _, _ := table.Next(rt.NilValue); !key.IsNil() {
			return scribe.Output{}, errors.New("NSE script dependencies are unsupported in this experimental profile")
		}
	}
	hostrule := env.Get(rt.StringValue("hostrule"))
	portrule := env.Get(rt.StringValue("portrule"))
	if hostrule.IsNil() == portrule.IsNil() {
		return scribe.Output{}, errors.New("NSE script must define exactly one hostrule or portrule")
	}
	host := rt.NewTable()
	address := task.Target.IP
	if address == "" && net.ParseIP(task.Target.Host) != nil {
		address = task.Target.Host
	}
	if address != "" {
		vm.SetEnv(host, "ip", rt.StringValue(address))
	}
	vm.SetEnv(host, "name", rt.StringValue(""))
	if net.ParseIP(task.Target.Host) == nil {
		vm.SetEnv(host, "targetname", rt.StringValue(task.Target.Host))
	}
	args := []rt.Value{rt.TableValue(host)}
	rule := hostrule
	phase := "hostrule"
	if !portrule.IsNil() {
		if task.Target.Port == 0 {
			return scribe.Output{}, errors.New("NSE portrule requires a supplied target port")
		}
		port := rt.NewTable()
		vm.SetEnv(port, "number", rt.IntValue(int64(task.Target.Port)))
		if task.Target.Protocol != "" {
			vm.SetEnv(port, "protocol", rt.StringValue(task.Target.Protocol))
		}
		if task.Target.State != "" {
			vm.SetEnv(port, "state", rt.StringValue(task.Target.State))
		}
		if task.Target.Service != "" {
			vm.SetEnv(port, "service", rt.StringValue(task.Target.Service))
		}
		if task.Target.TLS {
			version := rt.NewTable()
			vm.SetEnv(version, "service_tunnel", rt.StringValue("ssl"))
			vm.SetEnv(port, "version", rt.TableValue(version))
		}
		args = append(args, rt.TableValue(port))
		rule, phase = portrule, "portrule"
	}
	vm.SetEnv(env, "SCRIPT_TYPE", rt.StringValue(phase))
	matches, err := evaluateRule(ctx, vm, rule, args...)
	if err != nil {
		return scribe.Output{}, err
	}
	if !matches {
		return scribe.Output{Skipped: true}, nil
	}
	action := env.Get(rt.StringValue("action"))
	if _, ok := action.TryCallable(); !ok {
		return scribe.Output{}, errors.New("NSE action must be a function")
	}
	if err := ctx.Err(); err != nil {
		return scribe.Output{}, err
	}
	results := rt.NewTerminationWith(vm.MainThread().CurrentCont(), 2, false)
	if err := rt.Call(vm.MainThread(), action, args, results); err != nil {
		return scribe.Output{}, fmt.Errorf("NSE action: %w", err)
	}
	first, second := results.Get(0), results.Get(1)
	if first.IsNil() && second.IsNil() {
		return scribe.Output{}, nil
	}
	if !first.IsNil() && first.Type() != rt.StringType && first.Type() != rt.TableType {
		return scribe.Output{}, errors.New("NSE action output must be a table, string, or nil")
	}
	converter := newConversion(ctx, vm)
	data, err := converter.fromLua(first, 0)
	if err != nil {
		return scribe.Output{}, err
	}
	if !second.IsNil() {
		if first.Type() != rt.TableType || second.Type() != rt.StringType {
			return scribe.Output{}, errors.New("dual NSE output must be a table and string")
		}
		text, err := converter.fromLua(second, 0)
		if err != nil {
			return scribe.Output{}, err
		}
		data = map[string]any{"structured": data, "text": text}
	}
	output := scribe.Output{Data: data}
	return output, checkOutputSize(output)
}
