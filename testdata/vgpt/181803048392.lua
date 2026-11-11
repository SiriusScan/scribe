-- scribe: {"match":{"products":["Apache"],"protocols":["tcp"],"on_unknown":"run"}}
local function has_vulnerable_version(text)
  if type(text) ~= "string" then return false end
  for version in string.gmatch(text, "Apache/([%d%.]+)") do
    if version == "2.4.49" then return true end
  end
  return false
end

return {
  api_version = 1,
  rule = function(target, args)
    return target.protocol == "tcp" and target.port > 0
  end,
  action = function(target, args)
    local response = sirius.call("http.get", "/")
    local headers = response.headers or {}
    local server = headers["server"] or {}
    local evidence = nil

    for _, value in ipairs(server) do
      if has_vulnerable_version(value) then
        evidence = "GET / returned Server header: " .. value
        break
      end
    end

    if not evidence and has_vulnerable_version(response.body) then
      evidence = "GET / response body contains Apache/2.4.49."
    end

    if evidence then
      return {
        verdict = "vulnerable",
        data = {status = response.status, checked_path = "/", detected_version = "2.4.49"},
        findings = {{
          id = "apache-httpd-cve-2021-41773",
          title = "Apache httpd 2.4.49 detected (CVE-2021-41773)",
          severity = "high",
          evidence = evidence .. " Version-based detection; traversal exploitability depends on configuration and was not tested.",
          references = {"https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773"}
        }}
      }
    end

    return {
      verdict = "not_vulnerable",
      data = {status = response.status, checked_path = "/"},
      findings = {}
    }
  end
}
