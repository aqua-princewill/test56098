/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.commandinjection;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;

class CommandInjectionTask1Test {

  private final CommandInjectionTask1 task = new CommandInjectionTask1();

  @Test
  void semicolonInjectionMarksAssignmentSolved() {
    AttackResult result = task.ping("8.8.8.8; whoami");

    assertThat(result.assignmentSolved()).isTrue();
    assertThat(result.getOutput()).contains("Injection detected");
  }

  @Test
  void plainHostnameDoesNotSolveAssignment() {
    AttackResult result = task.ping("8.8.8.8");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).contains("Only ping executed");
  }

  @Test
  void blankHostFails() {
    AttackResult result = task.ping("   ");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).contains("Host is required");
  }
}
