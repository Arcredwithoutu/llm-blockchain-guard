/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.arcredwithoutu.blockchain.guard.core.blockchain;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class PemPrivateKeyRuleTest {

    private final PemPrivateKeyRule rule = new PemPrivateKeyRule();
    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");
    // 占位 body：纯结构标记，无真实密钥材料。
    private static final String PLACEHOLDER_BODY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    @Test
    void ecPrivateKeyBlockIsCritical() {
        String pem = "-----BEGIN EC PRIVATE KEY-----\n" + PLACEHOLDER_BODY
                + "\n-----END EC PRIVATE KEY-----";
        List<RuleMatch> m = rule.detect(pem, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.PEM_PRIVATE_KEY
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void opensshPrivateKeyHeaderIsCritical() {
        List<RuleMatch> m = rule.detect("-----BEGIN OPENSSH PRIVATE KEY-----", ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.PEM_PRIVATE_KEY);
    }

    @Test
    void plainPrivateKeyHeaderIsCritical() {
        List<RuleMatch> m = rule.detect("config: -----BEGIN PRIVATE KEY----- here", ctx);
        assertThat(m).anyMatch(r -> r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void publicKeyHeaderDoesNotMatch() {
        List<RuleMatch> m = rule.detect("-----BEGIN PUBLIC KEY-----\n" + PLACEHOLDER_BODY, ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void plainTextDoesNotMatch() {
        List<RuleMatch> m = rule.detect("this is just a private key discussion in prose", ctx);
        assertThat(m).isEmpty();
    }
}
