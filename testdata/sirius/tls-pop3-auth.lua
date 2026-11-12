-- Copyright (c) 2026 Sirius Scan. SPDX-License-Identifier: MIT
-- Original POP3 USER authentication policy observation; no CVE claim.
-- scribe: {"match":{"services":["pop3"],"products":["Scribe fixture"]}}
return {api_version=1, action=function()
  local r = sirius.call("tcp.exchange", "USER root\r\n")
  local verdict = "unknown"
  if r.data == "+OK logged in\r\n" then verdict = "vulnerable"
  elseif r.data == "-ERR authentication required\r\n" then verdict = "not_vulnerable" end
  if not r.tls then verdict = "unknown" end
  return {verdict=verdict, data={observation=r.data}}
end}
