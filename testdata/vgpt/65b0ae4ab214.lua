return {
  api_version = 1,
  rule = function(target, args)
    return target.protocol == "tcp" and target.port > 0
  end,
  action = function(target, args)
    local response = sirius.call("http.get", "/")
    local headers = response.headers or {}
    local server = headers["server"] or {}
    local source = nil

    local function matches_version(text)
      return type(text) == "string" and
        text:match("Apache/2%.4%.49%f[^%w%.]") ~= nil
    end

    for _, value in ipairs(server) do
      if matches_version(value) then
        source = "Server response header"
        break
      end
    end

    if not source and matches_version(response.body) then
      source = "HTTP response body"
    end

    if source then
      return {
        verdict = "vulnerable",
        data = { status = response.status, checked_path = "/" },
        findings = {
          {
            id = "apache-httpd-2-4-49-cve-2021-41773",
            title = "Apache httpd 2.4.49 detected (CVE-2021-41773)",
            severity = "high",
            evidence = source .. " identifies Apache/2.4.49. Version-based detection only; traversal and configuration prerequisites were not tested.",
            references = { "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773" }
          }
        }
      }
    end

    return {
      verdict = "not_vulnerable",
      data = { status = response.status, checked_path = "/", reason = "Exact Apache/2.4.49 version marker not observed." },
      findings = {}
    }
  end
}
