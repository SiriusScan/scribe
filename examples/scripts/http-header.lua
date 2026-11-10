-- Copyright (c) 2026 Sirius Scan. SPDX-License-Identifier: MIT
-- Demonstrates a local test marker, not detection of a real-world CVE.
return {
  api_version = 1,
  rule = function(target, args)
    return target.protocol == "tcp" and target.port > 0
  end,
  action = function(target, args)
    local response = sirius.call("http.get", args.path or "/")
    local marker = response.headers["x-sirius-fixture"]
    local findings = {}
    if marker and marker[1] == "vulnerable" then
      findings[1] = {
        id = "scribe-demo-marker",
        title = "Scribe demonstration fixture identified",
        severity = "info",
        evidence = "HTTP response header X-Sirius-Fixture: vulnerable",
        metadata = { demonstration = true }
      }
    end
    return {
      data = { status = response.status, checked_path = args.path or "/" },
      findings = findings
    }
  end
}
