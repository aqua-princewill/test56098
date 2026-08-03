/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.commandinjection;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.lessons.Category;

class CommandInjectionLessonMetadataTest {

  private final CommandInjection lesson = new CommandInjection();

  @Test
  void lessonMetadataMatchesRegistration() {
    assertThat(lesson.getDefaultCategory()).isEqualTo(Category.A3);
    assertThat(lesson.getTitle()).isEqualTo("commandinjection.title");
    assertThat(lesson.getId()).isEqualTo("CommandInjection");
    assertThat(lesson.getPackage()).isEqualTo("commandinjection");
  }
}
