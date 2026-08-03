/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class CommandInjectionIntegrationTest extends IntegrationTest {

  @Test
  public void runTests() {
    startLesson("CommandInjection");

    Map<String, Object> params = new HashMap<>();

    params.put("host", "8.8.8.8; whoami");
    checkAssignment(webGoatUrlConfig.url("CommandInjection/task1"), params, true);

    params.clear();
    params.put("host", "8.8.8.8%0awhoami");
    checkAssignment(webGoatUrlConfig.url("CommandInjection/task2"), params, true);

    params.clear();
    params.put("host", "8.8.8.8; whoami");
    checkAssignment(webGoatUrlConfig.url("CommandInjection/mitigation"), params, true);

    checkResults("CommandInjection");
  }
}
