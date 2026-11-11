-- Original Scribe fixture (MIT). Not an Nmap script; it pins documented
-- stdnse string/hex/time helper semantics.
local stdnse = require "stdnse"

description = [[Original fixture: stdnse pure helpers]]
categories = {"safe"}

hostrule = function()
  return true
end

action = function()
  local bad_hex, hex_err = stdnse.fromhex("xyz")
  local bad_time, time_err = stdnse.parse_timespec("10z")
  return {
    hex = stdnse.tohex("Scribe", {separator = ":"}),
    decoded = stdnse.fromhex("536372696265"),
    bad_hex_is_nil = bad_hex == nil,
    bad_hex_err_type = type(hex_err),
    timeout_seconds = stdnse.parse_timespec("2m"),
    bad_time_is_nil = bad_time == nil,
    bad_time_err = time_err,
    blank = stdnse.string_or_blank(stdnse.get_script_args("fixture.note")),
  }
end
