/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.commandinjection;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Task 1: Basic OS command injection. User input is concatenated into a shell command without
 * sanitization.
 */
@RestController
@AssignmentHints({"commandinjection.task1.hint1", "commandinjection.task1.hint2"})
public class CommandInjectionTask1 implements AssignmentEndpoint {

  @PostMapping("/CommandInjection/task1")
  @ResponseBody
  public AttackResult ping(@RequestParam("host") String host) {
    if (host == null || host.isBlank()) {
      return failed(this)
          .feedback("commandinjection.task1.failure")
          .output("Host is required")
          .build();
    }

    String command = "ping -c 1 " + host;

    if (hasCommandInjection(host)) {
      return success(this)
          .feedback("commandinjection.task1.success")
          .output(
              "Shell would run: "
                  + escape(command)
                  + "<br/>Injection detected: an additional command would execute.")
          .build();
    }

    return failed(this)
        .feedback("commandinjection.task1.failure")
        .output(
            "Shell would run: "
                + escape(command)
                + "<br/>Only ping executed (simulated). Try appending a shell metacharacter and"
                + " another command.")
        .build();
  }

  static boolean hasCommandInjection(String host) {
    return host.contains(";")
        || host.contains("&&")
        || host.contains("||")
        || host.contains("|")
        || host.contains("`")
        || host.contains("$(")
        || host.contains("\n");
  }

  private String escape(String value) {
    return value.replace("<", "&lt;").replace(">", "&gt;");
  }
}
