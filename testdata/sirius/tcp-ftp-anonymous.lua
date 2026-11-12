-- Copyright (c) 2026 Sirius Scan. SPDX-License-Identifier: MIT
-- Original bounded configuration observation; no CVE claim.
-- scribe: {"match":{"services":["http"],"products":["Scribe fixture"]}}
return {api_version=1, action=function()
  local r = sirius.call("tcp.exchange", "USER anonymous\r\n")
  local verdict = "unknown"
  if r.data == "331 Password required" then verdict = "vulnerable"
  elseif r.data == "530 Anonymous disabled" then verdict = "not_vulnerable" end
  return {verdict=verdict, data={observation=r.data}}
end}
