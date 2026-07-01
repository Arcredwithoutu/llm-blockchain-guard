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

import io.github.arcredwithoutu.blockchain.guard.core.codec.Base58Check;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import static org.assertj.core.api.Assertions.assertThat;

class BlockchainSecretDetectorTest {

    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");
    // 注入全部 11 条规则（协同回归保护）。
    private final BlockchainSecretDetector detector = new BlockchainSecretDetector(List.of(
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
            new PemPrivateKeyRule()));

    /** 运行时构造合法 checksum 的占位 WIF：version 0x80 + 32 字节占位 key（全 0）。 */
    private static String placeholderWif() {
        byte[] payload = new byte[33];
        payload[0] = (byte) 0x80;
        return Base58Check.encode(payload);
    }

    /** 64 个全 0 元素的占位 Solana keypair 字节数组（无真实密钥）。 */
    private static String zeroSolanaArray() {
        return "[" + IntStream.range(0, 64).mapToObj(i -> "0").collect(Collectors.joining(",")) + "]";
    }

    @Test
    void aggregatesThreeDistinctSecretsSortedByStart() {
        // 混合文本含三类不同密钥占位串：PEM 头（靠前）+ 私钥上下文 64hex（中）+ WIF（靠后）。
        String hex = "0000000000000000000000000000000000000000000000000000000000000001";
        String wif = placeholderWif();
        String text = "-----BEGIN EC PRIVATE KEY-----; 私钥: " + hex + " ; key=" + wif + ";";
        List<RuleMatch> matches = detector.detect(text, ctx);

        // 至少 3 类命中（PEM / EVM hex / WIF）
        assertThat(matches).hasSizeGreaterThanOrEqualTo(3);
        assertThat(matches).anyMatch(m -> m.entityType() == GuardEntityType.PEM_PRIVATE_KEY);
        assertThat(matches).anyMatch(m -> m.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX
                && m.riskLevel() == GuardRiskLevel.CRITICAL);
        assertThat(matches).anyMatch(m -> m.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_WIF);

        // 按 start 升序排列（协同排序保护）
        for (int i = 1; i < matches.size(); i++) {
            assertThat(matches.get(i).start()).isGreaterThanOrEqualTo(matches.get(i - 1).start());
        }
    }

    @Test
    void aggregatesKeystoreAndSolanaKeypair() {
        // Keystore JSON + Solana keypair 数组（两类结构化密钥共存）。
        String keystore = "{\"address\":\"0000000000000000000000000000000000000000\","
                + "\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"" + "0".repeat(64) + "\","
                + "\"kdf\":\"scrypt\",\"mac\":\"" + "0".repeat(64) + "\"},\"version\":3}";
        String text = keystore + " ; solana keypair id.json: " + zeroSolanaArray();
        List<RuleMatch> matches = detector.detect(text, ctx);

        assertThat(matches).anyMatch(m -> m.entityType() == GuardEntityType.BLOCKCHAIN_KEYSTORE_JSON);
        assertThat(matches).anyMatch(m -> m.entityType() == GuardEntityType.BLOCKCHAIN_SOLANA_KEYPAIR
                && m.riskLevel() == GuardRiskLevel.CRITICAL);
        for (int i = 1; i < matches.size(); i++) {
            assertThat(matches.get(i).start()).isGreaterThanOrEqualTo(matches.get(i - 1).start());
        }
    }

    @Test
    void plainTextProducesNoMatches() {
        List<RuleMatch> matches = detector.detect(
                "This is a normal sentence about wallets and keys without any secret.", ctx);
        assertThat(matches).isEmpty();
    }

    @Test
    void emptyTextProducesNoMatches() {
        assertThat(detector.detect("", ctx)).isEmpty();
        assertThat(detector.detect(null, ctx)).isEmpty();
    }

    @Test
    void hasAtLeastOneCriticalForBlockingDecision() {
        List<RuleMatch> matches = detector.detect("-----BEGIN OPENSSH PRIVATE KEY-----", ctx);
        assertThat(matches).anyMatch(m -> m.riskLevel() == GuardRiskLevel.CRITICAL);
    }
}
