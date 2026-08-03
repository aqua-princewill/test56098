/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;

class VulnerableComponentsCommonsCollectionsLessonTest {

  private final VulnerableComponentsCommonsCollectionsLesson lesson =
      new VulnerableComponentsCommonsCollectionsLesson();

  @Test
  void commonsCollectionsGadgetMarksAssignmentSolved() throws Exception {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
      oos.writeObject(new ConstantTransformer("gadget"));
    }
    String payload = Base64.getEncoder().encodeToString(baos.toByteArray());

    AttackResult result = lesson.completed(payload);

    assertThat(result.assignmentSolved()).isTrue();
    assertThat(result.getOutput()).contains("org.apache.commons.collections");
  }

  @Test
  void nonGadgetPayloadDoesNotSolveAssignment() {
    AttackResult result = lesson.completed(Base64.getEncoder().encodeToString("plain-text".getBytes()));

    assertThat(result.assignmentSolved()).isFalse();
  }

  @Test
  void detectsCommonsCollectionsClassNames() {
    assertThat(
            VulnerableComponentsCommonsCollectionsLesson.isCommonsCollectionsGadget(
                new ConstantTransformer("x")))
        .isTrue();
    assertThat(VulnerableComponentsCommonsCollectionsLesson.isCommonsCollectionsGadget("safe")).isFalse();
  }
}
