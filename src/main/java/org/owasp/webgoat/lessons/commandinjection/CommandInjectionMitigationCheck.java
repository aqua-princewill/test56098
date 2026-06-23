/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.commandinjection;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.regex.Pattern;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Mitigation assignment: demonstrate that an allowlist blocks injection while still permitting
 * safe hostnames.
 */
@RestController
@AssignmentHints({"commandinjection.mitigation.hint1", "commandinjection.mitigation.hint2"})
public class CommandInjectionMitigationCheck implements AssignmentEndpoint {

  private static final Pattern SAFE_HOST = Pattern.compile("^[a-zA-Z0-9.\\-]+$");
  private static final String DEFAULT_HOST = "8.8.8.8";

  @PostMapping("/CommandInjection/mitigation")
  @ResponseBody
  public AttackResult check(@RequestParam("host") String host) {
    if (host == null || host.isBlank()) {
      return failed(this)
          .feedback("commandinjection.mitigation.failure")
          .output("Host is required")
          .build();
    }

    if (SAFE_HOST.matcher(host).matches()) {
      return failed(this)
          .feedback("commandinjection.mitigation.failure")
          .output("Hostname passed allowlist. Submit a command injection payload to test mitigation.")
          .build();
    }

    String output =
        "Injection attempt blocked: "
            + escape(host)
            + "<br/>Safe fallback used: ping -c 1 "
            + DEFAULT_HOST;
    return success(this).feedback("commandinjection.mitigation.success").output(output).build();
  }

  private String escape(String value) {
    return value.replace("<", "&lt;").replace(">", "&gt;");
  }
}
