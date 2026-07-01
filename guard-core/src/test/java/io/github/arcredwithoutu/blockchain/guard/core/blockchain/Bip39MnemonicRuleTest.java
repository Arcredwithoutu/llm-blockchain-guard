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

class Bip39MnemonicRuleTest {

    private final Bip39MnemonicRule rule = new Bip39MnemonicRule(List.of("english"), true);
    private final Bip39MnemonicRule cnRule =
            new Bip39MnemonicRule(List.of("english", "chinese_simplified"), true);
    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");

    // BIP39 全零熵标准测试向量（公开，无资金）
    private static final String VALID_ZERO_ENTROPY =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // 中文全零熵 12 词向量：索引序列 [0]×11 + [3]（与语言无关）。
    // chinese_simplified 第 1 行=「的」(索引 0)、第 4 行=「在」(索引 3)。无空格连写。
    private static final String VALID_ZERO_ENTROPY_CN_PACKED = "的的的的的的的的的的的在";
    private static final String VALID_ZERO_ENTROPY_CN_SPACED = "的 的 的 的 的 的 的 的 的 的 的 在";

    @Test
    void validChecksumIsCritical() {
        List<RuleMatch> m = rule.detect(VALID_ZERO_ENTROPY, ctx);
        assertThat(m).hasSize(1);
        assertThat(m.get(0).entityType()).isEqualTo(GuardEntityType.BLOCKCHAIN_MNEMONIC);
        assertThat(m.get(0).riskLevel()).isEqualTo(GuardRiskLevel.CRITICAL);
    }

    @Test
    void detectsEnglishMnemonicGluedToChinesePrefixWithoutSpace() {
        // 验收 G2：中文前缀 + 全角括号/冒号无空格紧贴英文助记词，仍应 CRITICAL 检出
        // （连续词数不因「中文前缀+首词」黏成非 wordlist token 而跌破 12）。
        String text = "助记词（mnemonic）：" + VALID_ZERO_ENTROPY;
        List<RuleMatch> m = rule.detect(text, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_MNEMONIC
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void badChecksumWithoutContextNotCritical() {
        // 12 个合法词但末词改成破坏 checksum，且无 mnemonic 上下文
        String bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo";
        List<RuleMatch> m = rule.detect(bad, ctx);
        assertThat(m).noneMatch(r -> r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void badChecksumWithContextIsHigh() {
        String bad = "my seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo";
        List<RuleMatch> m = rule.detect(bad, ctx);
        assertThat(m).anyMatch(r -> r.riskLevel() == GuardRiskLevel.HIGH);
    }

    @Test
    void ordinarySentenceNoFalsePositive() {
        List<RuleMatch> m = rule.detect("the quick brown fox jumps over the lazy dog again and again", ctx);
        assertThat(m).isEmpty();
    }

    // B1：中文助记词常无空格连写，整串成一个 token 必查不到 → 必须逐字成 token 才能命中
    @Test
    void chinesePackedMnemonicIsCritical() {
        List<RuleMatch> m = cnRule.detect(VALID_ZERO_ENTROPY_CN_PACKED, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_MNEMONIC
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void chineseSpacedMnemonicIsCritical() {
        List<RuleMatch> m = cnRule.detect(VALID_ZERO_ENTROPY_CN_SPACED, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_MNEMONIC
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    // I1：英文助记词大小写变体（首字母大写）查表前未 lowercase 会漏检
    @Test
    void uppercaseEnglishMnemonicIsCritical() {
        String mixed = "Abandon Abandon Abandon Abandon Abandon Abandon "
                + "Abandon Abandon Abandon Abandon Abandon About";
        List<RuleMatch> m = rule.detect(mixed, ctx);
        assertThat(m).anyMatch(r -> r.riskLevel() == GuardRiskLevel.CRITICAL);
    }
}
