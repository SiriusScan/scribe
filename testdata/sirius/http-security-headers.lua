-- Copyright (c) 2026 Sirius Scan. SPDX-License-Identifier: MIT
-- Missing browser hardening headers are a configuration finding, not a CVE.
-- scribe: {"match":{"services":["http"],"products":["Scribe fixture"]}}
return {api_version=1, action=function()
  local response = sirius.call("http.get", "/")
  local verdict = "unknown"
  if response.status == 200 then
    local policy = response.headers["content-security-policy"]
    local nosniff = response.headers["x-content-type-options"]
    if policy and policy[1] and policy[1] ~= "" and nosniff and nosniff[1] == "nosniff" then
      verdict = "not_vulnerable"
    else verdict = "vulnerable" end
  end
  return {verdict=verdict, data={status=response.status}}
end}
