-- Copyright (c) 2026 Sirius Scan. SPDX-License-Identifier: MIT
-- Original controlled marker check; no real-world CVE claim.
-- scribe: {"match":{"services":["http"],"products":["Scribe fixture"]}}
return {api_version=1, action=function()
  local response = sirius.call("http.get", "/")
  local marker = response.headers["x-sirius-fixture"]
  local verdict = "unknown"
  if marker and marker[1] == "vulnerable" then verdict = "vulnerable"
  elseif marker and marker[1] == "clean" then verdict = "not_vulnerable" end
  return {verdict=verdict, data={status=response.status}}
end}
