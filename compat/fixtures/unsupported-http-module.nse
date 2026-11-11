-- Original Scribe fixture (MIT). The NSE http module is not part of
-- Scribe's experimental profile; this fixture pins that it is reported
-- as explicitly unsupported, never as a pass or a clean result.
local http = require "http"

description = [[Original fixture: unsupported http module]]
categories = {"safe"}

hostrule = function()
  return http ~= nil
end

action = function()
  return "unreachable"
end
