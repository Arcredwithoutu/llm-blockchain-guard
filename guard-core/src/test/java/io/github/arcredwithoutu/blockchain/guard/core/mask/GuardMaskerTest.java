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

package io.github.arcredwithoutu.blockchain.guard.core.mask;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class GuardMaskerTest {
    private final GuardMasker masker = new GuardMasker(new FingerprintService("unit-test-pepper"));

    @Test
    void maskRemovesSecretEntirely() {
        String secret = "a".repeat(64);
        String text = "私钥 " + secret + " end";
        GuardFinding f = new GuardFinding(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX,
                GuardRiskLevel.CRITICAL, 0.99, 3, 3 + 64, "evm-hex", "ctx", null);
        String masked = masker.apply(text, List.of(f));
        assertThat(masked).doesNotContain(secret);
        assertThat(masked).contains("[BLOCKCHAIN_SECRET:BLOCKCHAIN_PRIVATE_KEY_HEX:");
        assertThat(masked).endsWith(" end");
    }

    @Test
    void multipleSpansNoOffsetDrift() {
        String text = "x AAAA y BBBB z";
        GuardFinding f1 = new GuardFinding(GuardEntityType.API_KEY, GuardRiskLevel.HIGH, 0.9, 2, 6, "k", "", null);
        GuardFinding f2 = new GuardFinding(GuardEntityType.API_KEY, GuardRiskLevel.HIGH, 0.9, 9, 13, "k", "", null);
        String masked = masker.apply(text, List.of(f1, f2));
        assertThat(masked).doesNotContain("AAAA").doesNotContain("BBBB");
        assertThat(masked).startsWith("x ").contains(" y ").endsWith(" z");
    }

    @Test
    void addressKeepsHeadAndTail() {
        // 地址保留前后（0x1234...abcd 形态），不整值移除。
        String address = "0x1234567890abcdef1234567890abcdefABCDabcd";
        String text = "send to " + address + " now";
        GuardFinding f = new GuardFinding(GuardEntityType.BLOCKCHAIN_ADDRESS, GuardRiskLevel.LOW, 0.9,
                8, 8 + address.length(), "addr", "", null);
        String masked = masker.apply(text, List.of(f));
        assertThat(masked).contains("0x1234").contains("abcd").contains("...");
        assertThat(masked).doesNotContain(address);
    }

    @Test
    void piiPhoneMaskedWithSubtypeLabel() {
        String text = "phone 13800000000 end";
        GuardFinding f = new GuardFinding(GuardEntityType.PII, GuardRiskLevel.MEDIUM, 0.9,
                6, 6 + 11, "pii-cn-phone", "", null);
        String masked = masker.apply(text, List.of(f));
        assertThat(masked).contains("[PII:PHONE]").doesNotContain("13800000000");
    }

    @Test
    void piiEmailMaskedWithSubtypeLabel() {
        String text = "mail a@b.com end";
        GuardFinding f = new GuardFinding(GuardEntityType.PII, GuardRiskLevel.MEDIUM, 0.95,
                5, 12, "pii-email", "", null);
        assertThat(masker.apply(text, List.of(f))).contains("[PII:EMAIL]").doesNotContain("a@b.com");
    }

    @Test
    void piiIdCardAndBankCardMaskedWithSubtypeLabel() {
        String idText = "id 11010119900307123X end";
        GuardFinding idCard = new GuardFinding(GuardEntityType.PII, GuardRiskLevel.MEDIUM, 0.9,
                3, 3 + 18, "pii-cn-id-card", "", null);
        assertThat(masker.apply(idText, List.of(idCard))).contains("[PII:ID_CARD]");

        String bankText = "card 6225880137000000 end";
        GuardFinding bankCard = new GuardFinding(GuardEntityType.PII, GuardRiskLevel.MEDIUM, 0.7,
                5, 5 + 16, "pii-bank-card", "", null);
        assertThat(masker.apply(bankText, List.of(bankCard))).contains("[PII:BANK_CARD]");
    }

    @Test
    void piiPresidioEntityMaskedWithProviderType() {
        String text = "name John Smith!";
        GuardFinding f = new GuardFinding(GuardEntityType.PII, GuardRiskLevel.MEDIUM, 0.85,
                5, 15, "pii-presidio:PERSON", "", null);
        assertThat(masker.apply(text, List.of(f))).contains("[PII:PERSON]").doesNotContain("John Smith");
    }

    @Test
    void piiUnknownRuleFallsBackToGenericLabel() {
        String text = "x 13800000000 y";
        GuardFinding f = new GuardFinding(GuardEntityType.PII, GuardRiskLevel.MEDIUM, 0.5,
                2, 13, "something-else", "", null);
        assertThat(masker.apply(text, List.of(f))).contains("[PII:PII]");
    }

    @Test
    void injectionReplacedWithRemovalMarker() {
        String text = "x INJECT y";
        GuardFinding f = new GuardFinding(GuardEntityType.PROMPT_INJECTION, GuardRiskLevel.HIGH, 0.9,
                2, 8, "inj", "", null);
        String masked = masker.apply(text, List.of(f));
        assertThat(masked).contains("[REMOVED_UNTRUSTED_INSTRUCTION]").doesNotContain("INJECT");
    }

    @Test
    void credentialUsesSecretFormat() {
        String key = "ghp_" + "a".repeat(36);
        String text = "token " + key;
        GuardFinding f = new GuardFinding(GuardEntityType.API_KEY, GuardRiskLevel.HIGH, 0.9,
                6, 6 + key.length(), "github-pat", "", null);
        String masked = masker.apply(text, List.of(f));
        assertThat(masked).contains("[SECRET:API_KEY:").doesNotContain(key);
    }

    @Test
    void noFindingsReturnsOriginal() {
        String text = "nothing to mask here";
        assertThat(masker.apply(text, List.of())).isEqualTo(text);
    }
}
