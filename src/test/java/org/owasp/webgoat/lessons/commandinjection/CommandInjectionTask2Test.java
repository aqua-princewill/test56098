/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.commandinjection;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;

class CommandInjectionTask2Test {

  private final CommandInjectionTask2 task = new CommandInjectionTask2();

  @Test
  void newlineBypassMarksAssignmentSolved() {
    AttackResult result = task.ping("8.8.8.8%0awhoami");

    assertThat(result.assignmentSolved()).isTrue();
    assertThat(result.getOutput()).contains("Filter bypassed");
  }

  @Test
  void blockedSeparatorIsRejected() {
    AttackResult result = task.ping("8.8.8.8; whoami");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).contains("rejected by naive filter");
  }

  @Test
  void plainHostnameDoesNotSolveAssignment() {
    AttackResult result = task.ping("8.8.8.8");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).contains("No injection detected");
  }
}
