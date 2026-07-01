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

package io.github.arcredwithoutu.blockchain.guard.core.engine;

import io.github.arcredwithoutu.blockchain.guard.core.api.GuardrailService;
import io.github.arcredwithoutu.blockchain.guard.core.mask.FingerprintService;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardAction;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardDecision;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardDirection;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * PII 模块全链路集成测试（检测 → 策略 → 掩码）。
 *
 * <p>通过 {@link GuardrailFixtures#defaultService} 组装完整内核管线，
 * 验证 PII 在用户隐私场景与区块链隐私场景下的拦截、掩码能力。</p>
 */
@DisplayName("PII 模块全链路集成测试")
class PiiIntegrationTest {

    /** 合成假手机号（1[3-9] 前缀 + 9 位随机尾号，非真实号码）。 */
    private static final String SYNTHETIC_PHONE = "13800000000";
    /** 合成假手机号 2。 */
    private static final String SYNTHETIC_PHONE_2 = "13912345678";
    /** 合成假邮箱（example.com 为 RFC 2606 保留域名）。 */
    private static final String SYNTHETIC_EMAIL = "test@example.com";
    /** 合成假邮箱 2。 */
    private static final String SYNTHETIC_EMAIL_2 = "alice@foo.cn";
    /**
     * 合成假身份证（18 位，前 17 位 11010119900307888 + mod11-2 校验位 X）。
     * 结构合法、非真实、无资金、无链上历史。
     */
    private static final String SYNTHETIC_ID_CARD = "11010119900307088X";
    /** 合成假身份证 2（仅校验位不同）。 */
    private static final String SYNTHETIC_ID_CARD_2 = "11010119900307889X";
    /** 校验位错误的假身份证（末位 8 不正）。 */
    private static final String INVALID_ID_CARD = "110101199003070888";
    /**
     * 公开测试银行卡号（Luhn 合法，Visa 测试卡 4111111111111111）。
     * 此号码为支付行业公开测试数据，非真实账户。
     */
    private static final String SYNTHETIC_BANK_CARD = "4111111111111111";
    /** 公开测试银行卡号 2（Luhn 合法，Mastercard 测试卡）。 */
    private static final String SYNTHETIC_BANK_CARD_2 = "5500000000000004";
    /** Luhn 不合法的假银行卡号。 */
    private static final String INVALID_BANK_CARD = "4111111111111112";
    /**
     * 合成 EVM 私钥（范围内最小值 00..01，64hex，非真实钱包）。
     * 仅用于验证 PII+私钥共存时取最严 BLOCK 行为。
     */
    private static final String SYNTHETIC_PRIVATE_KEY =
            "0000000000000000000000000000000000000000000000000000000000000001";
    /** 合成 EVM 地址（40hex，公开非密材料）。 */
    private static final String SYNTHETIC_EVM_ADDR = "0x742d35Cc6634C0532925a3b8D4C9C5C5b1234abc";

    private final GuardrailService guard = GuardrailFixtures.defaultService("pii-integration-pepper");
    private final FingerprintService fingerprintService = new FingerprintService("pii-integration-pepper");

    // ============================================================
    // 1. 用户隐私场景 —— 正向（检测 + 掩码）
    // ============================================================

    @Nested
    @DisplayName("用户隐私正向：PII 检出并掩码")
    class UserPrivacyPositive {

        @Test
        @DisplayName("中国手机号 USER_INPUT → MASK + [PII:PHONE] + 零残留")
        void phoneInUserInputMasked() {
            String text = "我的手机号是 " + SYNTHETIC_PHONE + "，请帮我查询账户。";
            GuardDecision d = guard.inspect(text, GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .as("掩码后不含原文手机号")
                    .doesNotContain(SYNTHETIC_PHONE)
                    .as("掩码格式 [PII:PHONE]")
                    .contains("[PII:PHONE]");
            assertThat(d.findings())
                    .as("至少命中一个 PII finding")
                    .anySatisfy(f -> {
                        assertThat(f.entityType()).isEqualTo(GuardEntityType.PII);
                        assertThat(f.ruleId()).isEqualTo("pii-cn-phone");
                        assertThat(f.fingerprint()).matches("[0-9a-f]{8}");
                    });
            assertThat(d.blocked()).isFalse();
        }

        @Test
        @DisplayName("邮箱 MODEL_INPUT → MASK + [PII:EMAIL] + 零残留")
        void emailInModelInputMasked() {
            String text = "User email: " + SYNTHETIC_EMAIL + ", please send the report.";
            GuardDecision d = guard.inspect(text,
                    GuardContext.of(GuardDirection.MODEL_INPUT, "llm", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .doesNotContain(SYNTHETIC_EMAIL)
                    .contains("[PII:EMAIL]");
            assertThat(d.findings())
                    .anySatisfy(f -> assertThat(f.ruleId()).isEqualTo("pii-email"));
        }

        @Test
        @DisplayName("身份证 MEMORY_PERSIST → MASK + [PII:ID_CARD] + 零残留")
        void idCardInMemoryPersistMasked() {
            String text = "用户身份证 " + SYNTHETIC_ID_CARD + " 已存档。";
            GuardDecision d = guard.inspect(text,
                    GuardContext.of(GuardDirection.MEMORY_PERSIST, "mem", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .doesNotContain(SYNTHETIC_ID_CARD)
                    .contains("[PII:ID_CARD]");
            assertThat(d.findings())
                    .anySatisfy(f -> assertThat(f.ruleId()).isEqualTo("pii-cn-id-card"));
        }

        @Test
        @DisplayName("银行卡 TRACE_PERSIST → MASK + [PII:BANK_CARD] + 零残留")
        void bankCardInTracePersistMasked() {
            String text = "Payment: card=" + SYNTHETIC_BANK_CARD + " amount=100";
            GuardDecision d = guard.inspect(text,
                    GuardContext.of(GuardDirection.TRACE_PERSIST, "trace", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .doesNotContain(SYNTHETIC_BANK_CARD)
                    .contains("[PII:BANK_CARD]");
            assertThat(d.findings())
                    .anySatisfy(f -> assertThat(f.ruleId()).isEqualTo("pii-bank-card"));
        }

        @Test
        @DisplayName("多 PII 同现：手机+邮箱+身份证+银行卡 → 全部掩码 + 4 findings")
        void multiplePiiAllMasked() {
            String text = "用户信息：手机 " + SYNTHETIC_PHONE + "，邮箱 " + SYNTHETIC_EMAIL
                    + "，身份证 " + SYNTHETIC_ID_CARD + "，银行卡 " + SYNTHETIC_BANK_CARD + "。";
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .doesNotContain(SYNTHETIC_PHONE)
                    .doesNotContain(SYNTHETIC_EMAIL)
                    .doesNotContain(SYNTHETIC_ID_CARD)
                    .doesNotContain(SYNTHETIC_BANK_CARD)
                    .contains("[PII:PHONE]")
                    .contains("[PII:EMAIL]")
                    .contains("[PII:ID_CARD]")
                    .contains("[PII:BANK_CARD]");
            assertThat(d.findings()).hasSizeGreaterThanOrEqualTo(4);
        }

        @Test
        @DisplayName("同类型多 PII：两个邮箱 → 均掩码，2 findings")
        void multipleEmailsAllMasked() {
            String text = "联系 " + SYNTHETIC_EMAIL + " 或 " + SYNTHETIC_EMAIL_2;
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .doesNotContain(SYNTHETIC_EMAIL)
                    .doesNotContain(SYNTHETIC_EMAIL_2);
            assertThat(d.findings()).hasSizeGreaterThanOrEqualTo(2);
        }
    }

    // ============================================================
    // 2. 用户隐私场景 —— 负向（误报控制护栏）
    // ============================================================

    @Nested
    @DisplayName("用户隐私负向：误报控制")
    class UserPrivacyNegative {

        @Test
        @DisplayName("身份证校验位错 → 不命中，ALLOW")
        void invalidIdCardAllowed() {
            String text = "身份证 " + INVALID_ID_CARD + " 请核实";
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.ALLOW);
            assertThat(d.sanitizedText()).contains(INVALID_ID_CARD);
            assertThat(d.findings()).noneMatch(f -> f.entityType() == GuardEntityType.PII);
        }

        @Test
        @DisplayName("银行卡 Luhn 错 → 不命中，ALLOW")
        void invalidBankCardAllowed() {
            String text = "卡号 " + INVALID_BANK_CARD + " 是否有效";
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.ALLOW);
            assertThat(d.sanitizedText()).contains(INVALID_BANK_CARD);
            assertThat(d.findings()).noneMatch(f -> f.ruleId().equals("pii-bank-card"));
        }

        @Test
        @DisplayName("订单号（14位长数字，Luhn 失败）→ 不命中银行卡，ALLOW")
        void orderNumberNotDetectedAsPii() {
            String orderNum = "20260616123456";
            String text = "订单号 " + orderNum + " 已发货";
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            // 订单号 Luhn 不合法 → 不应被当银行卡。
            assertThat(d.findings()).noneMatch(f -> f.ruleId().equals("pii-bank-card"));
        }

        @Test
        @DisplayName("手机号嵌在长数字中 → 不命中（数字边界护栏）")
        void phoneEmbeddedInLongNumberNotDetected() {
            String text = "订单号 99138000000001234 包含手机形态数字";
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.findings()).noneMatch(f -> f.ruleId().equals("pii-cn-phone"));
        }

        @Test
        @DisplayName("含数字但非 PII → 全文 ALLOW")
        void cleanTextWithNumbersAllowed() {
            String text = "本次交易金额 1500.00 元，手续费 2.5 元，订单号 ORD-2026-001";
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.ALLOW);
            assertThat(d.findings()).noneMatch(f -> f.entityType() == GuardEntityType.PII);
        }

        @Test
        @DisplayName("含中文 PII 描述但不含真号码 → ALLOW")
        void piiDescriptionWithoutActualPiiAllowed() {
            String text = "请填写您的手机号码和电子邮箱地址，我们会尽快回复。";
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.findings()).noneMatch(f -> f.entityType() == GuardEntityType.PII);
        }
    }

    // ============================================================
    // 3. 区块链隐私场景 —— PII + 链上机密共存
    // ============================================================

    @Nested
    @DisplayName("区块链隐私：PII + 链上机密/地址共存")
    class BlockchainPrivacyCoexistence {

        @Test
        @DisplayName("PII（手机） + EVM 私钥同现 → BLOCK（取最严，CRITICAL 早停）")
        void piiWithPrivateKeyBlocked() {
            String text = "手机 " + SYNTHETIC_PHONE + "，私钥 0x" + SYNTHETIC_PRIVATE_KEY;
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action())
                    .as("私钥 CRITICAL → BLOCK")
                    .isEqualTo(GuardAction.BLOCK);
            assertThat(d.blocked()).isTrue();
            // BLOCK 时 sanitizedText 为安全占位，不含任何原文（含 PII）。
            assertThat(d.sanitizedText())
                    .doesNotContain(SYNTHETIC_PHONE)
                    .doesNotContain(SYNTHETIC_PRIVATE_KEY);
            // CRITICAL 私钥触发 localPreScrub 早停，PiiScanner 不会跑；
            // findings 仅含私钥实体（设计取最严已达成，审计齐全性为已知取舍）。
            assertThat(d.findings())
                    .anySatisfy(f -> assertThat(f.entityType())
                            .isEqualTo(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX));
        }

        @Test
        @DisplayName("PII（邮箱） + BIP39 助记词同现 → BLOCK（CRITICAL 早停）")
        void piiWithMnemonicBlocked() {
            String text = "邮箱 " + SYNTHETIC_EMAIL
                    + "，助记词 abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action())
                    .as("助记词 CRITICAL → BLOCK")
                    .isEqualTo(GuardAction.BLOCK);
            assertThat(d.sanitizedText()).doesNotContain(SYNTHETIC_EMAIL);
            // CRITICAL 早停，findings 仅含助记词实体。
            assertThat(d.findings())
                    .anySatisfy(f -> assertThat(f.entityType())
                            .isEqualTo(GuardEntityType.BLOCKCHAIN_MNEMONIC));
        }

        @Test
        @DisplayName("PII（身份证+银行卡） + 私钥三类同现 → BLOCK，多实体")
        void piiMultipleWithSecretBlocked() {
            String text = "KYC: ID=" + SYNTHETIC_ID_CARD + " 银行卡 " + SYNTHETIC_BANK_CARD
                    + "，私钥 0x" + SYNTHETIC_PRIVATE_KEY;
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.BLOCK);
            // 多 PII + 私钥均被阻断，安全占位不含任何机密。
            assertThat(d.sanitizedText())
                    .doesNotContain(SYNTHETIC_ID_CARD)
                    .doesNotContain(SYNTHETIC_BANK_CARD)
                    .doesNotContain(SYNTHETIC_PRIVATE_KEY);
        }

        @Test
        @DisplayName("PII（手机） + 区块链地址（非机密）→ PII MASK + 地址放行")
        void piiWithBlockchainAddressMaskedNotBlocked() {
            String text = "手机 " + SYNTHETIC_PHONE + "，钱包地址 " + SYNTHETIC_EVM_ADDR;
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            // 地址非私钥 → 不应 BLOCK。
            assertThat(d.action())
                    .as("地址非机密，仅 PII MASK")
                    .isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .as("手机号掩码")
                    .doesNotContain(SYNTHETIC_PHONE)
                    .contains("[PII:PHONE]")
                    .as("地址原样保留")
                    .contains(SYNTHETIC_EVM_ADDR);
        }

        @Test
        @DisplayName("仅区块链地址无 PII → ALLOW 放行")
        void blockchainAddressOnlyAllowed() {
            String text = "请查询地址 " + SYNTHETIC_EVM_ADDR + " 的余额";
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            // 地址非 PII、非私钥 → ALLOW。
            assertThat(d.action()).isEqualTo(GuardAction.ALLOW);
            assertThat(d.sanitizedText()).contains(SYNTHETIC_EVM_ADDR);
        }
    }

    // ============================================================
    // 4. 方向矩阵 —— PII 全方向 MASK
    // ============================================================

    @Nested
    @DisplayName("PII 方向矩阵：全 11 方向验证")
    class DirectionMatrix {

        /**
         * 提供全部 11 个 GuardDirection 枚举值，用于参数化测试。
         */
        static Stream<Arguments> allDirections() {
            return Stream.of(GuardDirection.values()).map(Arguments::of);
        }

        @ParameterizedTest(name = "[{index}] direction={0} → MASK + [PII:PHONE]")
        @MethodSource("allDirections")
        @DisplayName("PII(手机号) 在任意方向下均 MASK")
        void phoneMaskedInAllDirections(GuardDirection direction) {
            String text = "电话 " + SYNTHETIC_PHONE;
            GuardDecision d = guard.inspect(text,
                    GuardContext.of(direction, "src", "tr", "c", "u"));

            assertThat(d.action())
                    .as("PII 全方向应 MASK（policy uniform MASK）")
                    .isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .doesNotContain(SYNTHETIC_PHONE)
                    .contains("[PII:PHONE]");
            assertThat(d.findings())
                    .anySatisfy(f -> assertThat(f.ruleId()).isEqualTo("pii-cn-phone"));
        }

        @ParameterizedTest(name = "[{index}] direction={0} → MASK + [PII:EMAIL]")
        @MethodSource("allDirections")
        @DisplayName("PII(邮箱) 在任意方向下均 MASK")
        void emailMaskedInAllDirections(GuardDirection direction) {
            String text = "邮箱 " + SYNTHETIC_EMAIL;
            GuardDecision d = guard.inspect(text,
                    GuardContext.of(direction, "src", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .doesNotContain(SYNTHETIC_EMAIL)
                    .contains("[PII:EMAIL]");
        }
    }

    // ============================================================
    // 5. 掩码质量验证
    // ============================================================

    @Nested
    @DisplayName("掩码质量：零残留 + 格式 + 指纹非原文")
    class MaskQuality {

        @Test
        @DisplayName("PII 掩码后完整原文零残留")
        void piiMaskZeroResidual() {
            String text = "联系 " + SYNTHETIC_PHONE + " / " + SYNTHETIC_EMAIL
                    + " / ID:" + SYNTHETIC_ID_CARD + " / 卡:" + SYNTHETIC_BANK_CARD;
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            String sanitized = d.sanitizedText();
            assertThat(sanitized)
                    .as("手机号零残留").doesNotContain(SYNTHETIC_PHONE)
                    .as("邮箱零残留").doesNotContain(SYNTHETIC_EMAIL)
                    .as("身份证零残留").doesNotContain(SYNTHETIC_ID_CARD)
                    .as("银行卡零残留").doesNotContain(SYNTHETIC_BANK_CARD);
            // 掩码格式存在。
            assertThat(sanitized).contains("[PII:PHONE]", "[PII:EMAIL]",
                    "[PII:ID_CARD]", "[PII:BANK_CARD]");
        }

        @Test
        @DisplayName("PII finding span 边界精度：定位等于原文")
        void piiFindingSpanExactBoundary() {
            String phone = SYNTHETIC_PHONE;
            String prefix = "拨打 ";
            String suffix = " 咨询";
            String text = prefix + phone + suffix;
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.findings())
                    .anySatisfy(f -> {
                        assertThat(f.ruleId()).isEqualTo("pii-cn-phone");
                        assertThat(f.start()).isEqualTo(prefix.length());
                        assertThat(f.end()).isEqualTo(prefix.length() + phone.length());
                        assertThat(text.substring(f.start(), f.end())).isEqualTo(phone);
                    });
        }

        @Test
        @DisplayName("PII finding 携带 HMAC 指纹（非原文）")
        void piiFindingFingerprintNotRaw() {
            String text = "手机 " + SYNTHETIC_PHONE;
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.findings())
                    .anySatisfy(f -> {
                        assertThat(f.ruleId()).isEqualTo("pii-cn-phone");
                        // 指纹格式：8 位 hex。
                        assertThat(f.fingerprint()).matches("[0-9a-f]{8}");
                        // 指纹 ≠ 原文。
                        assertThat(f.fingerprint()).isNotEqualTo(SYNTHETIC_PHONE);
                        // 指纹 = 对原文 span 做 HMAC 的预期值。
                        String expectedFp = fingerprintService.fingerprint8(SYNTHETIC_PHONE);
                        assertThat(f.fingerprint()).isEqualTo(expectedFp);
                    });
        }

        @Test
        @DisplayName("各 PII 子类掩码格式正确")
        void piiSubtypeMaskFormats() {
            String text = "手机 " + SYNTHETIC_PHONE
                    + " 邮箱 " + SYNTHETIC_EMAIL
                    + " 身份证 " + SYNTHETIC_ID_CARD
                    + " 银行卡 " + SYNTHETIC_BANK_CARD;
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.sanitizedText())
                    .as("手机 → [PII:PHONE]").contains("[PII:PHONE]")
                    .as("邮箱 → [PII:EMAIL]").contains("[PII:EMAIL]")
                    .as("身份证 → [PII:ID_CARD]").contains("[PII:ID_CARD]")
                    .as("银行卡 → [PII:BANK_CARD]").contains("[PII:BANK_CARD]");
        }
    }

    // ============================================================
    // 6. 结构化/特殊场景
    // ============================================================

    @Nested
    @DisplayName("结构化文本与特殊场景")
    class StructuredAndSpecial {

        @Test
        @DisplayName("JSON 中含手机号 → MASK，结构保留")
        void jsonWithPhoneMaskedStructurePreserved() {
            String text = "{\"phone\":\"" + SYNTHETIC_PHONE + "\",\"name\":\"Alice\"}";
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .as("掩码后不含原文手机号")
                    .doesNotContain(SYNTHETIC_PHONE)
                    .as("包含掩码标记")
                    .contains("[PII:PHONE]")
                    .as("JSON 结构保留（key 存在）")
                    .contains("\"phone\"")
                    .contains("\"name\"");
        }

        @Test
        @DisplayName("表单格式 phone=...&email=... → 全文扫描命中")
        void formEncodedPiiDetected() {
            String text = "phone=" + SYNTHETIC_PHONE + "&email=" + SYNTHETIC_EMAIL;
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .doesNotContain(SYNTHETIC_PHONE)
                    .doesNotContain(SYNTHETIC_EMAIL);
        }

        @Test
        @DisplayName("中文语境含 PII 和英文混排")
        void mixedChineseEnglishPiiContext() {
            String text = "我的 email 是 " + SYNTHETIC_EMAIL + "，phone number 是 " + SYNTHETIC_PHONE;
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .doesNotContain(SYNTHETIC_EMAIL)
                    .doesNotContain(SYNTHETIC_PHONE);
            assertThat(d.findings()).hasSizeGreaterThanOrEqualTo(2);
        }

        @Test
        @DisplayName("两段 PII 中间隔非 PII 文本 → 均检出")
        void piiWithNonPiiSeparator() {
            String text = "手机 " + SYNTHETIC_PHONE + " 您好，感谢您的咨询。关于您的问题，请发送到邮箱 "
                    + SYNTHETIC_EMAIL + " 我们将尽快处理。";
            GuardDecision d = guard.inspect(text,
                    GuardContext.userInput("rag-chat", "tr", "c", "u"));

            assertThat(d.action()).isEqualTo(GuardAction.MASK);
            assertThat(d.sanitizedText())
                    .doesNotContain(SYNTHETIC_PHONE)
                    .doesNotContain(SYNTHETIC_EMAIL);
            assertThat(d.findings())
                    .filteredOn(f -> f.entityType() == GuardEntityType.PII)
                    .hasSizeGreaterThanOrEqualTo(2);
        }
    }
}
