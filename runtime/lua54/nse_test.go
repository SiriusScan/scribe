package lua54

import (
	"context"
	"strings"
	"testing"

	"github.com/SiriusScan/scribe"
)

func nseRuntime(t *testing.T) scribe.Runtime {
	t.Helper()
	runtime, err := NewNSE(Options{})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func nseRun(t *testing.T, source string, mutate func(*scribe.Task)) scribe.Output {
	t.Helper()
	input := task(scribe.NSE, source)
	if mutate != nil {
		mutate(&input)
	}
	output, err := nseRuntime(t).Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	return output
}

func TestStdNSEGetScriptArgsMultiple(t *testing.T) {
	output := nseRun(t, `local stdnse=require "stdnse"
hostrule=function() return true end
action=function()
  local a,b,c = stdnse.get_script_args("alpha","beta","gamma")
  local solo = stdnse.get_script_args("alpha")
  return {alpha=a, beta_type=type(b), gamma=c, solo=solo}
end`, func(input *scribe.Task) {
		input.Script.Args = map[string]any{"alpha": "fixture", "gamma": 7}
	})
	data := output.Data.(map[string]any)
	if data["alpha"] != "fixture" || data["beta_type"] != "nil" || data["gamma"] != int64(7) || data["solo"] != "fixture" {
		t.Fatalf("get_script_args: %#v", data)
	}
}

func TestStdNSEStringHelpers(t *testing.T) {
	output := nseRun(t, `local stdnse=require "stdnse"
hostrule=function() return true end
action=function(host)
  local bad, badmsg = stdnse.fromhex("abc")
  return {
    hostname = stdnse.get_hostname(host),
    passthrough = stdnse.get_hostname(" literal.example "),
    ip_only = stdnse.get_hostname({ip="192.0.2.9"}),
    named = stdnse.get_hostname({ip="192.0.2.9", name="reverse.example", targetname="target.example"}),
    reverse = stdnse.get_hostname({ip="192.0.2.9", name="reverse.example"}),
    blank_nil = stdnse.string_or_blank(nil),
    blank_empty = stdnse.string_or_blank(""),
    blank_value = stdnse.string_or_blank("present"),
    blank_custom = stdnse.string_or_blank("", "absent"),
    hex = stdnse.tohex("AB"),
    hex_sep = stdnse.tohex("abc", {separator=":"}),
    hex_group = stdnse.tohex("abc", {separator=":", group=4}),
    hex_int = stdnse.tohex(123456),
    hex_int_sep = stdnse.tohex(123456, {separator=":"}),
    decoded = stdnse.fromhex("41 42\t43"),
    bad_is_nil = bad == nil,
    bad_msg_type = type(badmsg),
  }
end`, func(input *scribe.Task) {
		input.Target.Host = "scanme.example"
		input.Target.IP = "192.0.2.4"
	})
	want := map[string]any{
		"hostname": "scanme.example", "passthrough": " literal.example ",
		"ip_only": "192.0.2.9", "named": "target.example", "reverse": "reverse.example",
		"blank_nil": "<blank>", "blank_empty": "<blank>", "blank_value": "present", "blank_custom": "absent",
		"hex": "4142", "hex_sep": "61:62:63", "hex_group": "61:6263", "hex_int": "1e240", "hex_int_sep": "1:e2:40",
		"decoded": "ABC", "bad_is_nil": true, "bad_msg_type": "string",
	}
	data := output.Data.(map[string]any)
	for key, value := range want {
		if data[key] != value {
			t.Errorf("%s = %#v, want %#v", key, data[key], value)
		}
	}
}

func TestStdNSEParseTimespec(t *testing.T) {
	output := nseRun(t, `local stdnse=require "stdnse"
hostrule=function() return true end
action=function()
  local bad, msg = stdnse.parse_timespec("10z")
  local junk, junkmsg = stdnse.parse_timespec("soon")
  return {plain=stdnse.parse_timespec("10"), ms=stdnse.parse_timespec("10ms"),
    sec=stdnse.parse_timespec("10S"), min=stdnse.parse_timespec("10m"),
    hour=stdnse.parse_timespec("1.5h"), bad_is_nil=bad==nil, bad_msg=msg,
    junk_is_nil=junk==nil, junk_msg_type=type(junkmsg)}
end`, nil)
	data := output.Data.(map[string]any)
	if data["plain"] != int64(10) || data["ms"] != 0.01 || data["sec"] != int64(10) ||
		data["min"] != int64(600) || data["hour"] != int64(5400) {
		t.Fatalf("parse_timespec values: %#v", data)
	}
	if data["bad_is_nil"] != true || data["bad_msg"] != `Can't parse time specification "10z" (bad unit "z")` {
		t.Fatalf("bad unit: %#v", data)
	}
	if data["junk_is_nil"] != true || data["junk_msg_type"] != "string" {
		t.Fatalf("junk spec: %#v", data)
	}
}

func TestStdNSEDiagnosticsAreSilentNoOps(t *testing.T) {
	output := nseRun(t, `local stdnse=require "stdnse"
hostrule=function() return true end
action=function()
  stdnse.debug(1, "value %s", "hidden")
  stdnse.debug1("hidden")
  stdnse.debug2("hidden %d", 3)
  stdnse.debug3("hidden")
  stdnse.verbose("hidden")
  stdnse.print_debug(1, "hidden")
  stdnse.print_verbose(2, "hidden")
  return "done"
end`, nil)
	if output.Data != "done" {
		t.Fatalf("diagnostics changed output: %#v", output)
	}
}

func TestShortportHTTPAndSSLRules(t *testing.T) {
	httpScript := `local shortport=require "shortport"
portrule=shortport.http
action=function() return "ran" end`
	if out := nseRun(t, httpScript, nil); out.Data != "ran" { // 8080/http/open/tcp
		t.Fatalf("http service should run: %#v", out)
	}
	if out := nseRun(t, httpScript, func(in *scribe.Task) {
		in.Target.Port, in.Target.Service = 80, ""
	}); out.Data != "ran" {
		t.Fatalf("http port 80 should run without a service fact: %#v", out)
	}
	if out := nseRun(t, httpScript, func(in *scribe.Task) {
		in.Target.Port, in.Target.Service = 2525, "smtp"
	}); !out.Skipped {
		t.Fatalf("non-http port should skip: %#v", out)
	}
	if out := nseRun(t, httpScript, func(in *scribe.Task) {
		in.Target.State = "closed"
	}); !out.Skipped {
		t.Fatalf("closed http port should skip: %#v", out)
	}

	sslScript := `local shortport=require "shortport"
portrule=shortport.ssl
action=function() return "ran" end`
	if out := nseRun(t, sslScript, func(in *scribe.Task) {
		in.Target.Port, in.Target.Service, in.Target.TLS = 9443, "custom", true
	}); out.Data != "ran" {
		t.Fatalf("ssl tunnel fact should run on any port: %#v", out)
	}
	if out := nseRun(t, sslScript, func(in *scribe.Task) {
		in.Target.Port, in.Target.Service, in.Target.TLS = 9443, "custom", false
	}); !out.Skipped {
		t.Fatalf("custom non-TLS service should skip ssl: %#v", out)
	}
	if out := nseRun(t, sslScript, func(in *scribe.Task) {
		in.Target.Port, in.Target.Service = 443, ""
	}); out.Data != "ran" {
		t.Fatalf("ssl port 443 should run: %#v", out)
	}
}

func TestShortportLikelyTables(t *testing.T) {
	output := nseRun(t, `local shortport=require "shortport"
portrule=shortport.port_or_service(shortport.LIKELY_HTTP_PORTS, shortport.LIKELY_HTTP_SERVICES)
action=function()
  return {http_port_count=#shortport.LIKELY_HTTP_PORTS, ssl_has_443=shortport.LIKELY_SSL_PORTS[1]==443}
end`, nil)
	data := output.Data.(map[string]any)
	if data["http_port_count"] == int64(0) || data["ssl_has_443"] != true {
		t.Fatalf("likely tables: %#v", data)
	}
}

func TestShortportPortRange(t *testing.T) {
	script := `local shortport=require "shortport"
portrule=shortport.port_range("T:8000-8010,U:53,9000-")
action=function() return "ran" end`
	cases := []struct {
		port  uint16
		proto string
		want  bool
	}{
		{8005, "tcp", true}, {8080, "tcp", false}, {53, "udp", true},
		{53, "tcp", false}, {9999, "udp", true}, {9999, "tcp", false},
	}
	for _, tc := range cases {
		out := nseRun(t, script, func(in *scribe.Task) {
			in.Target.Port, in.Target.Protocol, in.Target.Service = tc.port, tc.proto, ""
		})
		if ran := out.Data == "ran"; ran != tc.want {
			t.Errorf("%s/%d ran=%v want %v (out %#v)", tc.proto, tc.port, ran, tc.want, out)
		}
	}
	for _, bad := range []string{"T:foo", "9000-8000", "S:80", "T:", "70000"} {
		input := task(scribe.NSE, `local shortport=require "shortport";portrule=shortport.port_range("`+bad+`");action=function() return "ran" end`)
		if _, err := nseRuntime(t).Execute(context.Background(), input); err == nil {
			t.Errorf("port_range %q accepted", bad)
		}
	}
}

func TestShortportRejectsUnknownState(t *testing.T) {
	input := task(scribe.NSE, `local shortport=require "shortport";portrule=shortport.portnumber(80,"tcp",{"openn"});action=function() return "ran" end`)
	_, err := nseRuntime(t).Execute(context.Background(), input)
	if err == nil || !strings.Contains(err.Error(), "not a known port state") {
		t.Fatalf("unknown state should error, got %v", err)
	}
}

func TestStdNSEAndShortportStillRejectUnsupported(t *testing.T) {
	for _, source := range []string{
		`local s=require "shortport";portrule=s.version_port_or_service(443,"https");action=function() return "x" end`,
		`local s=require "stdnse";s.make_buffer(nil)`,
		`local s=require "stdnse";hostrule=function() return true end;action=function() return s.tohex(-1) end`,
	} {
		_, err := nseRuntime(t).Execute(context.Background(), task(scribe.NSE, source))
		if err == nil {
			t.Errorf("expected error for %q", source)
		}
	}
}
