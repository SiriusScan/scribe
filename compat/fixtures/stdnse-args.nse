-- Original Scribe fixture (MIT). Not an Nmap script; it pins the
-- documented stdnse.get_script_args multiple-return semantics and the
-- silent stdnse diagnostic calls.
local stdnse = require "stdnse"

description = [[Original fixture: script argument handling]]
categories = {"safe"}

hostrule = function(host)
  return host.ip ~= nil
end

action = function(host)
  stdnse.debug1("fixture starting for %s", host.ip)
  local first, missing, third = stdnse.get_script_args(
    "fixture.first", "fixture.absent", "fixture.third")
  local out = stdnse.output_table()
  out.first = first
  out.missing_is_nil = missing == nil
  out.third = third
  out.hostname = stdnse.get_hostname(host)
  return out
end
