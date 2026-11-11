-- Copyright (c) 2026 Sirius Scan. SPDX-License-Identifier: MIT
-- Original controlled marker check; no real-world CVE claim.
-- scribe: {"match":{"services":["http"],"products":["Scribe fixture"]}}
return {api_version=1, action=function()
  local response = sirius.call("tcp.exchange", "SCRIBE\r\n")
  local verdict = "unknown"
  if response.data == "vulnerable" then verdict = "vulnerable"
  elseif response.data == "clean" then verdict = "not_vulnerable" end
  return {verdict=verdict, data={marker=response.data}}
end}
