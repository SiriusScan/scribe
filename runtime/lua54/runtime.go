// Package lua54 implements bounded, isolated Lua 5.4 script profiles.
// Its NSE profile is an experimental subset, not a replacement for Nmap NSE.
package lua54

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/internal/thirdparty/golua/lib/base"
	"github.com/SiriusScan/scribe/internal/thirdparty/golua/lib/mathlib"
	"github.com/SiriusScan/scribe/internal/thirdparty/golua/lib/stringlib"
	"github.com/SiriusScan/scribe/internal/thirdparty/golua/lib/tablelib"
	"github.com/SiriusScan/scribe/internal/thirdparty/golua/lib/utf8lib"
	rt "github.com/SiriusScan/scribe/internal/thirdparty/golua/runtime"
)

// Limits accounts for Lua VM work; Memory is allocation accounting, not RSS.
// Zero values select finite defaults. Trusted Go capabilities must separately
// honor context cancellation and bound their own resources.
type Limits struct {
	CPU     uint64
	Memory  uint64
	Timeout time.Duration
}

type Options struct {
	Limits    Limits
	Functions map[string]scribe.Function
}

type runtime struct {
	dialect   scribe.Dialect
	limits    Limits
	functions map[string]scribe.Function
}

// NewNative creates the version 1 Sirius script profile.
func NewNative(options Options) (scribe.Runtime, error) { return newRuntime(scribe.Sirius, options) }

// NewNSE creates an experimental NSE-shaped profile with helper modules only.
// Native Go capabilities are deliberately unavailable to this profile.
func NewNSE(options Options) (scribe.Runtime, error) { return newRuntime(scribe.NSE, options) }

func newRuntime(dialect scribe.Dialect, options Options) (*runtime, error) {
	limits := options.Limits
	if limits.Timeout < 0 {
		return nil, errors.New("Lua timeout must be positive")
	}
	if limits.CPU == 0 {
		limits.CPU = 10_000_000
	}
	if limits.Memory == 0 {
		limits.Memory = 32 << 20
	}
	if limits.Timeout == 0 {
		limits.Timeout = 5 * time.Second
	}
	functions := make(map[string]scribe.Function, len(options.Functions))
	for name, function := range options.Functions {
		if name == "" || function == nil {
			return nil, errors.New("capability names and functions must be nonempty")
		}
		functions[name] = function
	}
	return &runtime{dialect: dialect, limits: limits, functions: functions}, nil
}

func (r *runtime) Dialect() scribe.Dialect { return r.dialect }

// Execute owns a fresh VM. Cancellation of CPU-only code is bounded by VM
// quotas; no goroutine attempts to mutate or interrupt a running interpreter.
func (r *runtime) Execute(ctx context.Context, task scribe.Task) (output scribe.Output, err error) {
	if ctx == nil {
		return output, errors.New("context is required")
	}
	if task.Script.Dialect != r.dialect {
		return output, errors.New("script dialect does not match runtime")
	}
	if len(task.Script.Source) == 0 || len(task.Script.Source) > scribe.MaxSourceBytes {
		return output, errors.New("Lua source must contain 1 to 1048576 bytes")
	}
	if err := task.Target.Validate(); err != nil {
		return output, err
	}
	if err := ctx.Err(); err != nil {
		return output, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.limits.Timeout)
	defer cancel()
	vm := rt.New(io.Discard)
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("Lua runtime panic: %v", recovered)
			output = scribe.Output{}
		}
	}()
	defer vm.Close(nil)
	duration := r.limits.Timeout
	if deadline, ok := ctx.Deadline(); ok {
		duration = min(duration, time.Until(deadline))
	}
	if duration <= 0 {
		return output, context.DeadlineExceeded
	}
	millis := uint64(duration / time.Millisecond)
	if duration%time.Millisecond != 0 {
		millis++
	}
	_, err = vm.MainThread().CallContext(rt.RuntimeContextDef{HardLimits: rt.RuntimeResources{Cpu: r.limits.CPU, Memory: r.limits.Memory, Millis: millis}}, func() error {
		modules := loadLibraries(vm)
		if r.dialect == scribe.Sirius {
			module := rt.NewTable()
			setFunction(vm, module, "call", r.capability(ctx, task.Target), 1, true)
			modules["sirius"] = rt.TableValue(module)
			vm.SetEnv(vm.GlobalEnv(), "sirius", modules["sirius"])
		} else if err := loadNSE(ctx, vm, task, modules); err != nil {
			return err
		}
		setFunction(vm, vm.GlobalEnv(), "require", func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
			name, err := c.StringArg(0)
			if err != nil {
				return nil, err
			}
			module, ok := modules[name]
			if !ok {
				return nil, fmt.Errorf("unsupported Lua module %q in %s profile", name, r.dialect)
			}
			return c.PushingNext1(t.Runtime, module), nil
		}, 1, false)
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk, err := vm.CompileAndLoadLuaChunk(task.Script.ID, task.Script.Source, rt.TableValue(vm.GlobalEnv()))
		if err != nil {
			return fmt.Errorf("load script: %w", err)
		}
		value, err := rt.Call1(vm.MainThread(), rt.FunctionValue(chunk))
		if err != nil {
			return fmt.Errorf("initialize script: %w", err)
		}
		if r.dialect == scribe.Sirius {
			output, err = runNative(ctx, vm, task, value)
		} else {
			output, err = runNSE(ctx, vm, task)
		}
		return err
	})
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		return scribe.Output{}, err
	}
	return output, nil
}

// Native dispatch can perform authorized I/O, so it does not claim IoSafe.
const compliance = rt.ComplyCpuSafe | rt.ComplyMemSafe | rt.ComplyTimeSafe

func setFunction(vm *rt.Runtime, table *rt.Table, name string, fn rt.GoFunctionFunc, count int, variadic bool) {
	vm.SetEnvGoFunc(table, name, fn, count, variadic).SolemnlyDeclareCompliance(compliance)
}

var baseOnce sync.Once
var baseValues map[string]rt.Value

func loadLibraries(vm *rt.Runtime) map[string]rt.Value {
	// Upstream base.Load mutates package-level GoFunction compliance flags.
	// Initialize those once before publishing immutable builtin values to jobs.
	baseOnce.Do(func() {
		prototype := rt.New(io.Discard)
		defer prototype.Close(nil)
		base.Load(prototype)
		baseValues = make(map[string]rt.Value)
		for _, name := range []string{"assert", "error", "ipairs", "next", "pairs", "pcall", "rawequal", "rawget", "rawlen", "rawset", "select", "tonumber", "tostring", "type", "xpcall", "_VERSION"} {
			baseValues[name] = prototype.GlobalEnv().Get(rt.StringValue(name))
		}
	})
	for name, value := range baseValues {
		vm.SetEnv(vm.GlobalEnv(), name, value)
	}
	vm.SetEnv(vm.GlobalEnv(), "_G", rt.TableValue(vm.GlobalEnv()))
	modules := make(map[string]rt.Value)
	for name, load := range map[string]func(*rt.Runtime) (rt.Value, func()){"string": stringlib.LibLoader.Load, "table": tablelib.LibLoader.Load, "math": mathlib.LibLoader.Load, "utf8": utf8lib.LibLoader.Load} {
		value, _ := load(vm)
		modules[name] = value
		vm.SetEnv(vm.GlobalEnv(), name, value)
	}
	vm.SetEnv(modules["string"].AsTable(), "dump", rt.NilValue)
	// Upstream randomseed changes process-global Go PRNG state. Keep jobs isolated.
	vm.SetEnv(modules["math"].AsTable(), "random", rt.NilValue)
	vm.SetEnv(modules["math"].AsTable(), "randomseed", rt.NilValue)
	return modules
}

func (r *runtime) capability(ctx context.Context, target scribe.Target) rt.GoFunctionFunc {
	return func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name, err := c.StringArg(0)
		if err != nil {
			return nil, err
		}
		function, ok := r.functions[name]
		if !ok {
			return nil, fmt.Errorf("unregistered Sirius capability %q", name)
		}
		converter := newConversion(ctx, t.Runtime)
		if len(c.Etc()) > MaxValueNodes {
			return nil, errors.New("capability argument count exceeds 10000")
		}
		arguments := make([]any, len(c.Etc()))
		for i, value := range c.Etc() {
			arguments[i], err = converter.fromLua(value, 0)
			if err != nil {
				return nil, fmt.Errorf("capability arguments: %w", err)
			}
		}
		value, err := function(ctx, target, arguments)
		if err != nil {
			return nil, fmt.Errorf("capability %q: %w", name, err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := newConversion(ctx, t.Runtime).toLua(value, 0)
		if err != nil {
			return nil, fmt.Errorf("capability %q result: %w", name, err)
		}
		return c.PushingNext1(t.Runtime, result), nil
	}
}

func runNative(ctx context.Context, vm *rt.Runtime, task scribe.Task, value rt.Value) (scribe.Output, error) {
	script, ok := value.TryTable()
	if !ok {
		return scribe.Output{}, errors.New("Sirius script must return a table")
	}
	version := script.Get(rt.StringValue("api_version"))
	if number, ok := version.TryInt(); !ok || number != 1 {
		return scribe.Output{}, errors.New("Sirius script api_version must be 1")
	}
	converter := newConversion(ctx, vm)
	target, err := converter.toLua(map[string]any{"host": task.Target.Host, "ip": task.Target.IP, "port": int(task.Target.Port), "protocol": task.Target.Protocol, "service": task.Target.Service, "state": task.Target.State, "tls": task.Target.TLS}, 0)
	if err != nil {
		return scribe.Output{}, err
	}
	args, err := converter.toLua(task.Script.Args, 0)
	if err != nil {
		return scribe.Output{}, fmt.Errorf("script args: %w", err)
	}
	if args.IsNil() {
		args = rt.TableValue(rt.NewTable())
	}
	if rule := script.Get(rt.StringValue("rule")); !rule.IsNil() {
		matches, err := evaluateRule(ctx, vm, rule, target, args)
		if err != nil {
			return scribe.Output{}, err
		}
		if !matches {
			return scribe.Output{Skipped: true}, nil
		}
	}
	action := script.Get(rt.StringValue("action"))
	if _, ok := action.TryCallable(); !ok {
		return scribe.Output{}, errors.New("script action must be a function")
	}
	if err := ctx.Err(); err != nil {
		return scribe.Output{}, err
	}
	result, err := rt.Call1(vm.MainThread(), action, target, args)
	if err != nil {
		return scribe.Output{}, fmt.Errorf("script action: %w", err)
	}
	return nativeOutput(ctx, vm, result)
}

func evaluateRule(ctx context.Context, vm *rt.Runtime, rule rt.Value, args ...rt.Value) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if _, ok := rule.TryCallable(); !ok {
		return false, errors.New("script rule must be a function")
	}
	value, err := rt.Call1(vm.MainThread(), rule, args...)
	if err != nil {
		return false, fmt.Errorf("script rule: %w", err)
	}
	result, ok := value.TryBool()
	if !ok {
		return false, errors.New("script rule must return a boolean")
	}
	return result, nil
}
