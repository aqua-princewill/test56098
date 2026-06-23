/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.commandinjection;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;

class CommandInjectionMitigationCheckTest {

  private final CommandInjectionMitigationCheck mitigation = new CommandInjectionMitigationCheck();

  @Test
  void injectionPayloadDemonstratesMitigation() {
    AttackResult result = mitigation.check("8.8.8.8; whoami");

    assertThat(result.assignmentSolved()).isTrue();
    assertThat(result.getOutput()).contains("Injection attempt blocked");
    assertThat(result.getOutput()).contains("Safe fallback used");
  }

  @Test
  void safeHostnameDoesNotDemonstrateMitigation() {
    AttackResult result = mitigation.check("8.8.8.8");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).contains("passed allowlist");
  }
}
