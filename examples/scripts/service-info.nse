-- Copyright (c) 2026 Sirius Scan. SPDX-License-Identifier: MIT
-- An original NSE-shaped fixture, not an upstream Nmap script.
local shortport = require "shortport"
local stdnse = require "stdnse"

description = "Returns the caller-supplied service facts without probing."
author = "Sirius Scan"
license = "MIT"
categories = { "safe", "discovery" }

portrule = shortport.port_or_service({80, 8080}, {"http"})

action = function(host, port)
  return {
    host = host.ip,
    port = port.number,
    service = port.service,
    label = stdnse.get_script_args("label") or "original Scribe fixture"
  }
end
