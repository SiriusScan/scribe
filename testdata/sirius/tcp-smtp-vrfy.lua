-- Copyright (c) 2026 Sirius Scan. SPDX-License-Identifier: MIT
-- Original exact SMTP VRFY policy observation; no mailbox enumeration or CVE claim.
-- scribe: {"match":{"services":["http"],"products":["Scribe fixture"]}}
return {api_version=1, action=function()
  local r = sirius.call("tcp.exchange", "VRFY root\r\n")
  local verdict = "unknown"
  if r.data == "250 root" then verdict = "vulnerable"
  elseif r.data == "502 Command not implemented" then verdict = "not_vulnerable" end
  return {verdict=verdict, data={observation=r.data}}
end}
