-- Copyright (c) 2026 Sirius Scan. SPDX-License-Identifier: MIT
-- Original bounded configuration observation; no CVE claim.
-- scribe: {"match":{"services":["http"],"products":["Scribe fixture"]}}
return {api_version=1, action=function()
  local r = sirius.call("tcp.exchange", "")
  local verdict = "unknown"
  if r.tls and r.tls.version == 769 then verdict = "vulnerable"
  elseif r.tls and r.tls.version == 771 then verdict = "not_vulnerable" end
  return {verdict=verdict, data={observation=r.data}}
end}
