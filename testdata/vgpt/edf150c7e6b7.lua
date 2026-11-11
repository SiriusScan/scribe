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

    local function vulnerable_version(text)
      return type(text) == "string" and
        text:find("Apache/2%.4%.49%f[^%w_.-]") ~= nil
    end

    local evidence = nil
    for _, server in ipairs(servers) do
      if vulnerable_version(server) then
        evidence = "HTTP Server header advertises: " .. server
        break
      end
    end
    if not evidence and vulnerable_version(body) then
      evidence = "HTTP response body contains the exact version banner Apache/2.4.49."
    end

    if evidence then
      return {
        verdict = "vulnerable",
        data = {status = response.status, checked_path = "/", detection = "version-based; exploitability not verified"},
        findings = {{
          id = "apache-httpd-cve-2021-41773",
          title = "Apache httpd 2.4.49 detected (CVE-2021-41773)",
          severity = "high",
          evidence = evidence .. " This release is affected by CVE-2021-41773; exploitability depends on server configuration.",
          references = {"https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773"}
        }}
      }
    end

    return {
      verdict = "not_vulnerable",
      data = {status = response.status, checked_path = "/", detection = "No exact Apache/2.4.49 banner observed; version-based check only."},
      findings = {}
    }
  end
}
