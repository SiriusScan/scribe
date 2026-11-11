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
    local evidence = nil

    local function matches_version(value)
      return type(value) == "string" and
        string.find(value, "Apache/2%.4%.49%f[^%w%.]") ~= nil
    end

    for _, value in ipairs(servers) do
      if matches_version(value) then
        evidence = "Server header advertises the affected version: " .. value
        break
      end
    end
    if not evidence and matches_version(body) then
      evidence = "HTTP response body contains the exact affected version token Apache/2.4.49."
    end

    if evidence then
      return {
        verdict = "vulnerable",
        data = { status = response.status, checked_path = "/", detection = "version-based" },
        findings = {
          {
            id = "apache-httpd-2449-cve-2021-41773",
            title = "Apache httpd 2.4.49 detected (CVE-2021-41773)",
            severity = "high",
            evidence = evidence .. " Version-based detection only; traversal exploitability depends on server configuration.",
            references = { "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773" }
          }
        }
      }
    end

    return {
      verdict = "not_vulnerable",
      data = { status = response.status, checked_path = "/", detection = "version-based" },
      findings = {}
    }
  end
}
