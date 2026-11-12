-- Copyright (c) 2026 Sirius Scan. SPDX-License-Identifier: MIT
-- Original Redis PING authentication policy observation; no CVE claim.
-- scribe: {"match":{"services":["redis"],"products":["Scribe fixture"]}}
return {api_version=1, action=function()
  local r = sirius.call("tcp.exchange", "*1\r\n$4\r\nPING\r\n")
  local verdict = "unknown"
  if r.data == "+PONG\r\n" then verdict = "vulnerable"
  elseif r.data == "-NOAUTH Authentication required.\r\n" then verdict = "not_vulnerable" end
  if not r.tls then verdict = "unknown" end
  return {verdict=verdict, data={observation=r.data}}
end}
