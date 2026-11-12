-- Copyright (c) 2026 Sirius Scan. SPDX-License-Identifier: MIT
-- Original bounded configuration observation; no CVE claim.
-- scribe: {"match":{"services":["http"],"products":["Scribe fixture"]}}
return {api_version=1, action=function()
  local r = sirius.call("http.get", "/")
  local verdict = "unknown"
  if r.status == 200 and r.body == "<title>Index of /</title>" then verdict = "vulnerable"
  elseif r.status == 403 then verdict = "not_vulnerable" end
  return {verdict=verdict, data={observation=r.status}}
end}
