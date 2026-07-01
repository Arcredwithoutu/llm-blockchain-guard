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

package io.github.arcredwithoutu.blockchain.guard.core.scanner;

import io.github.arcredwithoutu.blockchain.guard.core.blockchain.Bip39MnemonicRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.BlockchainSecretDetector;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.BitcoinWifRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.CardanoSigningKeyRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.EvmPrivateKeyHexRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.ExtendedKeyRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.KeystoreJsonRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.PemPrivateKeyRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.SolanaKeypairRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.StellarSeedRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.SubstrateSecretUriRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.SuiPrivateKeyRule;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class BlockchainSecretScannerTest {

    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");
    private final BlockchainSecretScanner scanner = new BlockchainSecretScanner(
            new BlockchainSecretDetector(List.of(
                    new EvmPrivateKeyHexRule(true),
                    new Bip39MnemonicRule(List.of("english"), true),
                    new BitcoinWifRule(),
                    new ExtendedKeyRule(),
                    new SolanaKeypairRule(),
                    new SuiPrivateKeyRule(),
                    new SubstrateSecretUriRule(),
                    new CardanoSigningKeyRule(),
                    new StellarSeedRule(),
                    new KeystoreJsonRule(),
                    new PemPrivateKeyRule())));

    // 范围内占位（全 0 末位 1，合法范围但非真实钱包）。
    private static final String IN_RANGE =
            "0000000000000000000000000000000000000000000000000000000000000001";

    @Test
    void mapsRuleMatchToFindingWithNullFingerprint() {
        List<GuardFinding> findings = scanner.scan("私钥: " + IN_RANGE, ctx);
        assertThat(findings).anyMatch(f -> f.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX
                && f.riskLevel() == GuardRiskLevel.CRITICAL
                && f.fingerprint() == null);
    }

    @Test
    void jsonFieldSpanMappedBackToOriginalOffset() {
        // 私钥藏在 JSON 字段 value 里，全文路径靠字段名上下文命中，字段路径靠 value 内独立检测。
        String json = "{\"note\":\"hi\",\"privkey\":\"" + IN_RANGE + "\"}";
        List<GuardFinding> findings = scanner.scan(json, ctx);
        assertThat(findings).anyMatch(f -> f.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX
                && json.substring(f.start(), f.end()).equals(IN_RANGE));
    }

    @Test
    void overlappingSpansDeduplicatedKeepingLarger() {
        // 同一私钥：全文路径命中带 0x 前缀（更大 span），字段路径命中裸 64hex（更小 span），
        // 二者重叠且同 entityType → 去重后仅剩 1 条，且保留更大 span（含 0x）。
        String json = "{\"privkey\":\"0x" + IN_RANGE + "\"}";
        List<GuardFinding> hexFindings = scanner.scan(json, ctx).stream()
                .filter(f -> f.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX)
                .toList();
        assertThat(hexFindings).hasSize(1);
        // 保留更大 span：覆盖串以 0x 起头（含前缀）。
        assertThat(json.substring(hexFindings.get(0).start(), hexFindings.get(0).end()))
                .startsWith("0x").contains(IN_RANGE);
    }

    @Test
    void cleanTextProducesNoFindings() {
        assertThat(scanner.scan("以太坊和比特币的区别是什么？", ctx)).isEmpty();
    }

    @Test
    void snakeCaseFieldNameProvidesPositiveContext() {
        // G5：字段名 private_key（下划线）应作正向上下文，使 contextRequired 下的 in-range 64hex 被检出。
        // value 为裸 64hex 无 0x：全文路径与字段路径都缺独立上下文，仅靠字段名上下文才命中。
        String json = "{\"note\":\"hi\",\"private_key\":\"" + IN_RANGE + "\"}";
        List<GuardFinding> findings = scanner.scan(json, ctx);
        assertThat(findings).anyMatch(f -> f.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX
                && f.riskLevel() == GuardRiskLevel.CRITICAL
                && json.substring(f.start(), f.end()).equals(IN_RANGE));
    }

    @Test
    void nestedFieldPathProvidesWalletKeyContext() {
        // G5：嵌套路径 wallet.key 派生 "wallet key" 上下文（叶子键 key 单独过泛，靠路径组合命中）。
        String json = "{\"wallet\":{\"key\":\"" + IN_RANGE + "\"}}";
        List<GuardFinding> findings = scanner.scan(json, ctx);
        assertThat(findings).anyMatch(f -> f.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX
                && json.substring(f.start(), f.end()).equals(IN_RANGE));
    }

    @Test
    void sensitiveFieldNameWithNonKeyValueProducesNoFinding() {
        // G5 Part B：字段名仅作上下文增强，value 非密钥格式不命中（避免纯字段名误阻断）。
        assertThat(scanner.scan("{\"private_key\":\"not_a_real_key_value_123\"}", ctx)).isEmpty();
    }

    @Test
    void supportsAllContexts() {
        assertThat(scanner.supports(ctx)).isTrue();
    }
}
