/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.deserialization.SerializationHelper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Demonstrates risk from Apache Commons Collections 3.2.1 (CVE-2015-4852) when unsafe Java
 * deserialization is combined with gadget classes from that library.
 */
@RestController
@AssignmentHints({
  "vulnerable-components.commons-collections.hint1",
  "vulnerable-components.commons-collections.hint2"
})
public class VulnerableComponentsCommonsCollectionsLesson implements AssignmentEndpoint {

  @PostMapping("/VulnerableComponents/attack2")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    if (StringUtils.isEmpty(payload)) {
      return failed(this).feedback("vulnerable-components.commons-collections.empty").build();
    }

    try {
      Object obj = SerializationHelper.fromString(sanitize(payload));
      if (isCommonsCollectionsGadget(obj)) {
        return success(this)
            .feedback("vulnerable-components.commons-collections.success")
            .output("Deserialized gadget class: " + obj.getClass().getName())
            .build();
      }
      return failed(this)
          .feedback("vulnerable-components.commons-collections.wrong-type")
          .output("Deserialized: " + obj.getClass().getName())
          .build();
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-components.commons-collections.error")
          .output(ex.getMessage())
          .build();
    }
  }

  static boolean isCommonsCollectionsGadget(Object obj) {
    return obj.getClass().getName().startsWith("org.apache.commons.collections.");
  }

  private String sanitize(String payload) {
    return payload
        .replace("+", "")
        .replace("\r", "")
        .replace("\n", "")
        .replace("> ", ">")
        .replace(" <", "<");
  }
}
