-- scribe: {"match":{"products":["Apache"],"protocols":["tcp"],"on_unknown":"run"}}
local function has_version(value)
  if type(value) ~= "string" then return false end
  return (value .. " "):match("Apache/2%.4%.49[^%w%._%-]") ~= nil
end

return {
  api_version = 1,
  action = function(target, args)
    local response = sirius.call("http.get", "/")
    local headers = response.headers or {}
    local server_values = headers["server"] or {}
    local evidence = nil

    for _, value in ipairs(server_values) do
      if has_version(value) then
        evidence = "GET / returned Server header: " .. value
        break
      end
    end

    if not evidence and has_version(response.body) then
      evidence = "GET / response body contains the exact Apache/2.4.49 version identifier."
    end

    if evidence then
      return {
        verdict = "vulnerable",
        data = { status = response.status, checked_path = "/", detection_method = "version identification; exploitability not tested" },
        findings = {
          {
            id = "apache-httpd-cve-2021-41773",
            title = "Apache httpd 2.4.49 identified (CVE-2021-41773)",
            severity = "high",
            evidence = evidence,
            references = { "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773" },
            metadata = { software = "Apache httpd", version = "2.4.49", cve = "CVE-2021-41773", version_based = true }
          }
        }
      }
    end

    return {
      verdict = "not_vulnerable",
      data = { status = response.status, checked_path = "/", reason = "Exact Apache/2.4.49 version identifier not observed." },
      findings = {}
    }
  end
}
