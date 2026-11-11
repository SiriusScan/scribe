-- Original Scribe fixture (MIT). Not an Nmap script; it pins the
-- shortport.http portrule over supplied port facts.
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[Original fixture: shortport.http rule]]
categories = {"safe"}

portrule = shortport.http

action = function(host, port)
  return {
    service = stdnse.string_or_blank(port.service),
    number = port.number,
    state = port.state,
  }
end
