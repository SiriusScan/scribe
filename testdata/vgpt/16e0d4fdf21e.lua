-- scribe: {"match":{"products":["Apache"],"protocols":["tcp"],"on_unknown":"run"}}
local function has_vulnerable_version(value)
  if type(value) ~= "string" then return false end
  for version in string.gmatch(string.lower(value), "apache/([%d%.]+)") do
    if version == "2.4.49" then return true end
  end
  return false
end

return {
  api_version = 1,
  action = function(target, args)
    local response = sirius.call("http.get", "/")
    local headers = response.headers or {}
    local servers = headers["server"] or {}
    local evidence = nil

    for _, value in ipairs(servers) do
      if has_vulnerable_version(value) then
        evidence = "GET / returned Server: " .. value
        break
      end
    end

    if not evidence and has_vulnerable_version(response.body) then
      evidence = "GET / response body contains the exact Apache/2.4.49 version signature."
    end

    if evidence then
      return {
        verdict = "vulnerable",
        data = {status = response.status, checked_path = "/", detection = "version-based"},
        findings = {{
          id = "apache-httpd-cve-2021-41773",
          title = "Apache httpd 2.4.49 detected (CVE-2021-41773)",
          severity = "high",
          evidence = evidence .. " Version-based detection; exploitable configuration was not verified.",
          references = {"https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773"}
        }}
      }
    end

    return {
      verdict = "not_vulnerable",
      data = {status = response.status, checked_path = "/", detection = "version-based"},
      findings = {}
    }
  end
}
