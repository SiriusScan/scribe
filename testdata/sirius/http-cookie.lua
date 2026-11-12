-- Copyright (c) 2026 Sirius Scan. SPDX-License-Identifier: MIT
-- Checks an explicitly returned session cookie; absence is inconclusive.
-- scribe: {"match":{"services":["http"],"products":["Scribe fixture"]}}
return {api_version=1, action=function()
  local r = sirius.call("http.get", "/")
  local verdict = "unknown"
  local cookies = r.headers["set-cookie"]
  if r.status == 200 and cookies and cookies[1] then
    local cookie = string.lower(cookies[1])
    if string.find(cookie, "session=", 1, true) == 1 then
      if string.find(cookie, "; secure", 1, true) and string.find(cookie, "; httponly", 1, true) then
        verdict = "not_vulnerable"
      else verdict = "vulnerable" end
    end
  end
  return {verdict=verdict, data={status=r.status}}
end}
