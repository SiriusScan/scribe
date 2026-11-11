package lua54

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
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
	// Documented NSE semantics: each name argument yields one return value
	// (nil when the caller supplied no such argument), in argument order.
	setFunction(vm, stdnse, "get_script_args", func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
		names := c.Etc()
		if len(names) > 1024 {
			return nil, errors.New("stdnse.get_script_args accepts at most 1024 names")
		}
		values := make([]rt.Value, len(names))
		for i, raw := range names {
			name, ok := raw.TryString()
			if !ok {
				return nil, fmt.Errorf("stdnse.get_script_args name #%d must be a string", i+1)
			}
			values[i] = args.AsTable().Get(rt.StringValue(name))
		}
		return c.PushingNext(t.Runtime, values...), nil
	}, 0, true)
	setFunction(vm, stdnse, "output_table", func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
		return c.PushingNext1(t.Runtime, rt.TableValue(rt.NewTable())), nil
	}, 0, false)
	setFunction(vm, stdnse, "get_hostname", stdnseGetHostname, 1, false)
	setFunction(vm, stdnse, "string_or_blank", stdnseStringOrBlank, 2, false)
	setFunction(vm, stdnse, "tohex", stdnseTohex, 2, false)
	setFunction(vm, stdnse, "fromhex", stdnseFromhex, 1, false)
	setFunction(vm, stdnse, "parse_timespec", stdnseParseTimespec, 1, false)
	// Scribe is a silent library with no verbosity channel. Diagnostic calls
	// are accepted and discarded, matching an Nmap run at verbosity/debug 0
	// for the default levels scripts pass; they never become output.
	for _, name := range []string{"debug", "debug1", "debug2", "debug3", "verbose", "print_debug", "print_verbose"} {
		setFunction(vm, stdnse, name, func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
			return c.PushingNext(t.Runtime), nil
		}, 0, true)
	}
	strictModule(vm, "stdnse", stdnse)
	modules["stdnse"] = rt.TableValue(stdnse)
	shortport := rt.NewTable()
	setFunction(vm, shortport, "portnumber", shortportFactory("number"), 3, false)
	setFunction(vm, shortport, "service", shortportFactory("service"), 3, false)
	setFunction(vm, shortport, "port_or_service", shortportFactory("either"), 4, false)
	setFunction(vm, shortport, "port_range", shortportPortRange, 1, false)
	vm.SetEnv(shortport, "LIKELY_HTTP_PORTS", intListValue(vm, likelyHTTPPorts))
	vm.SetEnv(shortport, "LIKELY_HTTP_SERVICES", stringListValue(vm, likelyHTTPServices))
	vm.SetEnv(shortport, "LIKELY_SSL_PORTS", intListValue(vm, likelySSLPorts))
	vm.SetEnv(shortport, "LIKELY_SSL_SERVICES", stringListValue(vm, likelySSLServices))
	vm.SetEnv(shortport, "http", rt.FunctionValue(newShortportRule(intSet(likelyHTTPPorts), stringSetOf(likelyHTTPServices), defaultProtos(), defaultStates(), "")))
	vm.SetEnv(shortport, "ssl", rt.FunctionValue(newShortportRule(intSet(likelySSLPorts), stringSetOf(likelySSLServices), defaultProtos(), defaultStates(), "ssl")))
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

// Scribe's initial likely-service sets. They are documented Scribe behavior
// pinned by first-party fixtures, not a claim of byte-for-byte parity with
// any specific upstream nselib revision.
var (
	likelyHTTPPorts    = []int64{80, 443, 631, 8008, 8080, 8088, 8180, 8443, 9080, 9090}
	likelyHTTPServices = []string{"http", "https", "http-proxy", "ipp"}
	likelySSLPorts     = []int64{443, 465, 636, 8443, 989, 990, 992, 993, 995, 5061}
	likelySSLServices  = []string{"https", "ssl", "imaps", "pop3s", "ldaps", "ftps"}
)

func intSet(values []int64) map[int64]bool {
	set := make(map[int64]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func stringSetOf(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func defaultProtos() map[string]bool { return map[string]bool{"tcp": true} }
func defaultStates() map[string]bool { return map[string]bool{"open": true, "open|filtered": true} }
func knownStates() map[string]bool {
	return map[string]bool{"open": true, "closed": true, "filtered": true, "unfiltered": true, "open|filtered": true, "closed|filtered": true}
}

func intListValue(vm *rt.Runtime, values []int64) rt.Value {
	table := rt.NewTable()
	for i, value := range values {
		vm.SetTable(table, rt.IntValue(int64(i+1)), rt.IntValue(value))
	}
	return rt.TableValue(table)
}

func stringListValue(vm *rt.Runtime, values []string) rt.Value {
	table := rt.NewTable()
	for i, value := range values {
		vm.SetTable(table, rt.IntValue(int64(i+1)), rt.StringValue(value))
	}
	return rt.TableValue(table)
}

// newShortportRule builds a (host, port) -> boolean rule over supplied port
// facts only. Unknown protocol/state/service facts never match. When tunnel
// is nonempty, a port.version.service_tunnel equal to it also matches.
func newShortportRule(numbers map[int64]bool, services, protocols, states map[string]bool, tunnel string) *rt.GoFunction {
	rule := rt.NewGoFunction(func(t *rt.Thread, call *rt.GoCont) (rt.Cont, error) {
		port, err := call.TableArg(1)
		if err != nil {
			return nil, err
		}
		protocol, _ := port.Get(rt.StringValue("protocol")).TryString()
		state, _ := port.Get(rt.StringValue("state")).TryString()
		number, _ := port.Get(rt.StringValue("number")).TryInt()
		service, _ := port.Get(rt.StringValue("service")).TryString()
		matches := numbers[number] || services[service]
		if !matches && tunnel != "" {
			if version, ok := port.Get(rt.StringValue("version")).TryTable(); ok {
				got, _ := version.Get(rt.StringValue("service_tunnel")).TryString()
				matches = got == tunnel
			}
		}
		matches = protocols[protocol] && states[state] && matches
		return call.PushingNext1(t.Runtime, rt.BoolValue(matches)), nil
	}, "shortport rule", 2, false)
	rule.SolemnlyDeclareCompliance(compliance)
	return rule
}

func stdnseGetHostname(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	value := c.Arg(0)
	if text, ok := value.TryString(); ok {
		return c.PushingNext1(t.Runtime, rt.StringValue(text)), nil
	}
	table, ok := value.TryTable()
	if !ok {
		return nil, errors.New("stdnse.get_hostname requires a host table or string")
	}
	for _, field := range []string{"targetname", "name", "ip"} {
		if text, ok := table.Get(rt.StringValue(field)).TryString(); ok && text != "" {
			return c.PushingNext1(t.Runtime, rt.StringValue(text)), nil
		}
	}
	return c.PushingNext1(t.Runtime, rt.StringValue("")), nil
}

func stdnseStringOrBlank(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	blank := "<blank>"
	if !c.Arg(1).IsNil() {
		text, ok := c.Arg(1).TryString()
		if !ok {
			return nil, errors.New("stdnse.string_or_blank blank value must be a string")
		}
		blank = text
	}
	value := c.Arg(0)
	if value.IsNil() {
		return c.PushingNext1(t.Runtime, rt.StringValue(blank)), nil
	}
	text, ok := value.TryString()
	if !ok {
		return nil, errors.New("stdnse.string_or_blank requires a string or nil")
	}
	if text == "" {
		text = blank
	}
	return c.PushingNext1(t.Runtime, rt.StringValue(text)), nil
}

func stdnseTohex(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	var digits string
	value := c.Arg(0)
	if text, ok := value.TryString(); ok {
		t.RequireMem(uint64(2*len(text) + 64))
		digits = hex.EncodeToString([]byte(text))
	} else if number, ok := value.TryInt(); ok {
		if number < 0 {
			return nil, errors.New("stdnse.tohex requires a non-negative integer")
		}
		digits = strconv.FormatInt(number, 16)
	} else {
		return nil, errors.New("stdnse.tohex requires a string or integer")
	}
	separator, group := "", 2
	if !c.Arg(1).IsNil() {
		options, ok := c.Arg(1).TryTable()
		if !ok {
			return nil, errors.New("stdnse.tohex options must be a table")
		}
		if raw := options.Get(rt.StringValue("separator")); !raw.IsNil() {
			text, ok := raw.TryString()
			if !ok {
				return nil, errors.New("stdnse.tohex separator must be a string")
			}
			separator = text
		}
		if raw := options.Get(rt.StringValue("group")); !raw.IsNil() {
			size, ok := raw.TryInt()
			if !ok || size < 1 || size > 1024 {
				return nil, errors.New("stdnse.tohex group must be an integer between 1 and 1024")
			}
			group = int(size)
		}
	}
	if separator != "" && len(digits) > group {
		first := len(digits) % group
		if first == 0 {
			first = group
		}
		parts := []string{digits[:first]}
		for rest := digits[first:]; len(rest) > 0; rest = rest[group:] {
			parts = append(parts, rest[:group])
		}
		digits = strings.Join(parts, separator)
	}
	return c.PushingNext1(t.Runtime, rt.StringValue(digits)), nil
}

func stdnseFromhex(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	text, err := c.StringArg(0)
	if err != nil {
		return nil, err
	}
	fail := func(message string) (rt.Cont, error) {
		return c.PushingNext(t.Runtime, rt.NilValue, rt.StringValue(message)), nil
	}
	cleaned := strings.Join(strings.Fields(text), "")
	if len(cleaned)%2 != 0 {
		return fail("hex string must contain an even number of digits")
	}
	t.RequireMem(uint64(len(cleaned)/2 + 64))
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return fail(fmt.Sprintf("cannot decode hex string: %v", err))
	}
	return c.PushingNext1(t.Runtime, rt.StringValue(string(decoded))), nil
}

func stdnseParseTimespec(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	spec, err := c.StringArg(0)
	if err != nil {
		return nil, err
	}
	fail := func(message string) (rt.Cont, error) {
		return c.PushingNext(t.Runtime, rt.NilValue, rt.StringValue(message)), nil
	}
	trimmed := strings.TrimSpace(spec)
	i := 0
	for i < len(trimmed) && (trimmed[i] >= '0' && trimmed[i] <= '9' || trimmed[i] == '.') {
		i++
	}
	if i == 0 {
		return fail(fmt.Sprintf("Can't parse time specification %q", spec))
	}
	amount, err := strconv.ParseFloat(trimmed[:i], 64)
	if err != nil {
		return fail(fmt.Sprintf("Can't parse time specification %q", spec))
	}
	var factor float64
	switch unit := trimmed[i:]; strings.ToLower(unit) {
	case "", "s":
		factor = 1
	case "ms":
		factor = 0.001
	case "m":
		factor = 60
	case "h":
		factor = 3600
	default:
		return fail(fmt.Sprintf("Can't parse time specification %q (bad unit %q)", spec, unit))
	}
	seconds := amount * factor
	if seconds == math.Trunc(seconds) && math.Abs(seconds) <= math.MaxInt64 {
		return c.PushingNext1(t.Runtime, rt.IntValue(int64(seconds))), nil
	}
	return c.PushingNext1(t.Runtime, rt.FloatValue(seconds)), nil
}

// shortportPortRange parses an Nmap-style port specification such as
// "T:80,1-30,U:31337,21-25". Unprefixed leading entries match either
// protocol; T:/U: switch the protocol for following entries. Entries may
// be single ports, "a-b", "a-", "-b", or "-" (all ports).
func shortportPortRange(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	spec, err := c.StringArg(0)
	if err != nil {
		return nil, err
	}
	tcpPorts, udpPorts := make(map[int64]bool), make(map[int64]bool)
	section := "" // "" = either protocol
	add := func(lo, hi int64) {
		t.RequireMem(uint64(16 * (hi - lo + 1)))
		for port := lo; port <= hi; port++ {
			if section != "udp" {
				tcpPorts[port] = true
			}
			if section != "tcp" {
				udpPorts[port] = true
			}
		}
	}
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, errors.New("shortport port_range contains an empty entry")
		}
		if len(token) >= 2 && token[1] == ':' {
			switch token[0] {
			case 'T', 't':
				section = "tcp"
			case 'U', 'u':
				section = "udp"
			default:
				return nil, fmt.Errorf("shortport port_range protocol %q is unsupported; use T or U", token[:1])
			}
			token = token[2:]
			if token == "" {
				return nil, errors.New("shortport port_range entry has a protocol but no port")
			}
		}
		loText, hiText, isRange := token, token, strings.Contains(token, "-")
		if isRange {
			parts := strings.SplitN(token, "-", 2)
			loText, hiText = parts[0], parts[1]
			if strings.Contains(hiText, "-") {
				return nil, fmt.Errorf("shortport port_range entry %q is malformed", token)
			}
			if loText == "" {
				loText = "1"
			}
			if hiText == "" {
				hiText = "65535"
			}
		}
		lo, errLo := strconv.ParseInt(loText, 10, 64)
		hi, errHi := strconv.ParseInt(hiText, 10, 64)
		if errLo != nil || errHi != nil || lo < 1 || hi > 65535 || lo > hi {
			return nil, fmt.Errorf("shortport port_range entry %q is not a port or range within 1-65535", token)
		}
		add(lo, hi)
	}
	states := defaultStates()
	t.RequireMem(128)
	rule := rt.NewGoFunction(func(t *rt.Thread, call *rt.GoCont) (rt.Cont, error) {
		port, err := call.TableArg(1)
		if err != nil {
			return nil, err
		}
		protocol, _ := port.Get(rt.StringValue("protocol")).TryString()
		state, _ := port.Get(rt.StringValue("state")).TryString()
		number, _ := port.Get(rt.StringValue("number")).TryInt()
		matches := states[state] && (protocol == "tcp" && tcpPorts[number] || protocol == "udp" && udpPorts[number])
		return call.PushingNext1(t.Runtime, rt.BoolValue(matches)), nil
	}, "shortport range rule", 2, false)
	rule.SolemnlyDeclareCompliance(compliance)
	return c.PushingNext1(t.Runtime, rt.FunctionValue(rule)), nil
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
		for state := range states {
			if !knownStates()[state] {
				return nil, fmt.Errorf("shortport state %q is not a known port state", state)
			}
		}
		t.RequireMem(128)
		rule := newShortportRule(numbers, services, protocols, states, "")
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
		if !ok || entry == "" {
			return errors.New("shortport lists must contain nonempty strings")
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
