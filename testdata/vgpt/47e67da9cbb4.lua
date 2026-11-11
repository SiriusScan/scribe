return {
  api_version = 1,
  rule = function(target, args)
    return target.protocol == "tcp" and target.port > 0
  end,
  action = function(target, args)
    local response = sirius.call("http.get", "/")
    local headers = response.headers or {}
    local server_values = headers["server"] or {}
    local evidence = nil

    local function matches_version(text)
      return type(text) == "string" and
        (string.lower(text) .. " "):find("apache/2%.4%.49[^%w%.]") ~= nil
    end

    for _, value in ipairs(server_values) do
      if matches_version(value) then
        evidence = "HTTP Server header: " .. value
        break
      end
    end

    if not evidence and matches_version(response.body) then
      evidence = "HTTP response body contains the exact Apache/2.4.49 version banner."
    end

    local data = { status = response.status, checked_path = "/" }
    if evidence then
      return {
        verdict = "vulnerable",
        data = data,
        findings = {
          {
            id = "apache-httpd-cve-2021-41773",
            title = "Apache httpd 2.4.49 detected (CVE-2021-41773)",
            severity = "high",
            evidence = evidence,
            references = { "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773" },
            metadata = { detection = "version-banner", exploitation_confirmed = false }
          }
        }
      }
    end

    return { verdict = "not_vulnerable", data = data, findings = {} }
  end
}
