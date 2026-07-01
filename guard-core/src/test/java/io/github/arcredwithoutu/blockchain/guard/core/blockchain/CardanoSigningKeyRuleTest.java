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

class CardanoSigningKeyRuleTest {

    private final CardanoSigningKeyRule rule = new CardanoSigningKeyRule();
    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");
    // 占位 .skey：type 标记齐全、cborHex 为占位（全 0），无真实密钥材料。
    private static final String PAYMENT_SKEY = "{"
            + "\"type\":\"PaymentSigningKeyShelley_ed25519\","
            + "\"description\":\"Payment Signing Key\","
            + "\"cborHex\":\"5820" + "0".repeat(64) + "\"}";

    @Test
    void paymentSigningKeyIsCritical() {
        List<RuleMatch> m = rule.detect(PAYMENT_SKEY, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_CARDANO_SIGNING_KEY
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void extendedSigningKeyIsCritical() {
        String extended = PAYMENT_SKEY.replace("PaymentSigningKeyShelley_ed25519",
                "PaymentExtendedSigningKeyShelley_ed25519_bip32");
        List<RuleMatch> m = rule.detect(extended, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_CARDANO_SIGNING_KEY);
    }

    @Test
    void verificationKeyDoesNotMatch() {
        // VerificationKey（公钥）不含 SigningKey 标记，不应命中。
        String vkey = PAYMENT_SKEY.replace("PaymentSigningKeyShelley_ed25519",
                "PaymentVerificationKeyShelley_ed25519");
        List<RuleMatch> m = rule.detect(vkey, ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void signingKeyTypeWithoutCborHexDoesNotMatch() {
        String noCbor = "{\"type\":\"PaymentSigningKeyShelley_ed25519\",\"description\":\"x\"}";
        List<RuleMatch> m = rule.detect(noCbor, ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void plainTextDoesNotMatch() {
        List<RuleMatch> m = rule.detect("the cardano signing key cborHex format", ctx);
        assertThat(m).isEmpty();
    }
}
