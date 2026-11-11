-- Original Scribe fixture (MIT). Worker threads are not part of
-- Scribe's experimental profile; this fixture pins the explicit
-- unsupported-API error.
local stdnse = require "stdnse"

description = [[Original fixture: unsupported stdnse.new_thread]]
categories = {"safe"}

hostrule = function()
  return true
end

action = function()
  return stdnse.new_thread(function() end)
end
