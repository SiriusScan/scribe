-- Original Scribe fixture (MIT). Not an Nmap script; it pins
-- shortport.port_range and the likely-HTTP tables used together in
-- one action assertion.
local shortport = require "shortport"

description = [[Original fixture: shortport.port_range rule]]
categories = {"safe"}

portrule = shortport.port_range("T:8000-8100,U:53")

action = function(host, port)
  return {
    number = port.number,
    protocol = port.protocol,
    likely_http_first = shortport.LIKELY_HTTP_PORTS[1],
  }
end
