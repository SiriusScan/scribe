return {
  api_version = 1,
  rule = function(target, args)
    return target.protocol == "tcp" and target.port > 0
  end,
  action = function(target, args)
    local response = sirius.call("http.get", "/")
    local headers = response.headers or {}
    local servers = headers["server"] or {}
    local body = response.body or ""

    local function matches_version(text)
      return string.find(text, "Apache/2%.4%.49%f[^%w%.%-]") ~= nil
    end

    local evidence = nil
    for _, server in ipairs(servers) do
      if matches_version(server) then
        evidence = "GET / returned Server: " .. server
        break
      end
    end
    if not evidence and matches_version(body) then
      evidence = "GET / response body contains the exact Apache/2.4.49 version token."
    end

    if evidence then
      return {
        verdict = "vulnerable",
        data = {status = response.status, checked_path = "/", detection = "version-based"},
        findings = {{
          id = "apache-httpd-cve-2021-41773",
          title = "Apache httpd 2.4.49 detected (CVE-2021-41773)",
          severity = "high",
          evidence = evidence .. " Version-based detection; path traversal exploitability depends on server configuration and was not tested.",
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
