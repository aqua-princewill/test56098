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
 * Task 2: Naive blacklist filter blocks common separators but can be bypassed with alternative
 * injection techniques.
 */
@RestController
@AssignmentHints({"commandinjection.task2.hint1", "commandinjection.task2.hint2"})
public class CommandInjectionTask2 implements AssignmentEndpoint {

  private static final String[] BLOCKED = {";", "&&", "|"};

  @PostMapping("/CommandInjection/task2")
  @ResponseBody
  public AttackResult ping(@RequestParam("host") String host) {
    if (host == null || host.isBlank()) {
      return failed(this)
          .feedback("commandinjection.task2.failure")
          .output("Host is required")
          .build();
    }

    for (String blocked : BLOCKED) {
      if (host.contains(blocked)) {
        return failed(this)
            .feedback("commandinjection.task2.failure")
            .output("Input rejected by naive filter (blocked: " + escape(blocked) + ")")
            .build();
      }
    }

    String command = "ping -c 1 " + host;

    if (bypassesFilter(host)) {
      return success(this)
          .feedback("commandinjection.task2.success")
          .output(
              "Shell would run: "
                  + escape(command)
                  + "<br/>Filter bypassed: alternative injection technique detected.")
          .build();
    }

    return failed(this)
        .feedback("commandinjection.task2.failure")
        .output(
            "Shell would run: "
                + escape(command)
                + "<br/>No injection detected yet. The filter blocks ;, &&, and |.")
        .build();
  }

  static boolean bypassesFilter(String host) {
    return host.contains("\n")
        || host.contains("%0a")
        || host.contains("%0A")
        || host.contains("`")
        || host.contains("$(")
        || host.contains("${");
  }

  private String escape(String value) {
    return value.replace("<", "&lt;").replace(">", "&gt;");
  }
}
