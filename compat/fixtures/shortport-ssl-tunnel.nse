-- Original Scribe fixture (MIT). Not an Nmap script; it pins the
-- shortport.ssl portrule, including a supplied TLS service tunnel fact
-- on a nonstandard port.
local shortport = require "shortport"

description = [[Original fixture: shortport.ssl rule]]
categories = {"safe"}

portrule = shortport.ssl

action = function(host, port)
  return {number = port.number, tunnel = port.version.service_tunnel}
end
