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

import io.github.arcredwithoutu.blockchain.guard.core.codec.Secp256k1Range;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * EVM 64hex 私钥检测规则：曲线范围 + 上下文联合判定，并识别 Aptos AIP-80 前缀。
 * <ul>
 *   <li>AIP-80 前缀（ed25519-priv-0x / secp256k1-priv-0x）→ 直接 CRITICAL（不依赖 secp256k1 范围）</li>
 *   <li>正向上下文优先：正向上下文 + 曲线范围内 → CRITICAL/0.95（确定性 secret 不被负向上下文对抗降级）</li>
 *   <li>仅在无正向上下文时，负向上下文（tx_hash/sha256 等）→ 不出 finding（同形哈希交地址扫描器识别为 TX_HASH，§6.11）</li>
 *   <li>无任何上下文且 contextRequired → 跳过；否则曲线范围内判 MEDIUM</li>
 * </ul>
 */
public final class EvmPrivateKeyHexRule implements DetectionRule {

    private static final String RULE_ID = "evm-privkey-hex";
    private static final int WINDOW = 48;
    // AIP-80 前缀 + 64hex（前缀已强信号，无需 0x 前的曲线范围判定）
    private static final Pattern AIP80 = Pattern.compile("(?i)(?:ed25519|secp256k1)-priv-0x[0-9a-f]{64}");
    private static final Pattern HEX64 = Pattern.compile("(?i)(?:0x)?[0-9a-f]{64}");
    private static final List<String> POSITIVE_CONTEXT = List.of(
            "private key", "privkey", "privatekey", "secret key", "wallet key",
            "私钥", "秘钥", "钱包密钥");
    private static final List<String> NEGATIVE_CONTEXT = List.of(
            "tx_hash", "block_hash", "sha256", "merkle", "transactiondigest");

    private final boolean contextRequired;
    private final ContextWindowScorer scorer = new ContextWindowScorer(WINDOW);

    public EvmPrivateKeyHexRule(boolean contextRequired) {
        this.contextRequired = contextRequired;
    }

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<RuleMatch> detect(String text, GuardContext ctx) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        List<RuleMatch> matches = new ArrayList<>();
        List<int[]> covered = new ArrayList<>();
        Matcher aip = AIP80.matcher(text);
        while (aip.find()) {
            covered.add(new int[] {aip.start(), aip.end()});
            matches.add(new RuleMatch(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX, GuardRiskLevel.CRITICAL,
                    0.98, aip.start(), aip.end(), RULE_ID, "AIP-80 prefixed private key"));
        }
        Matcher hex = HEX64.matcher(text);
        while (hex.find()) {
            if (isCovered(hex.start(), covered)) {
                continue;
            }
            RuleMatch match = evaluateHex(text, hex.start(), hex.end());
            if (match != null) {
                matches.add(match);
            }
        }
        return matches;
    }

    private RuleMatch evaluateHex(String text, int start, int end) {
        boolean inRange = isValidCurveKey(text, start, end);
        // 正向上下文优先：对抗者在同窗口塞负向词不应把真私钥降级。
        if (scorer.hasAnyContext(text, start, end, POSITIVE_CONTEXT)) {
            if (inRange) {
                return new RuleMatch(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX, GuardRiskLevel.CRITICAL,
                        0.95, start, end, RULE_ID, "private-key context + valid secp256k1 range");
            }
            return new RuleMatch(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX, GuardRiskLevel.HIGH,
                    0.6, start, end, RULE_ID, "private-key context but out of secp256k1 range");
        }
        // 仅无正向上下文时才考虑负向上下文：tx_hash/sha256/merkle 等同形哈希，私钥规则不出 finding，
        // 交 BlockchainAddressScanner 将 0x+64hex 识别为 BLOCKCHAIN_TX_HASH（设计 §6.11，避免误阻断链上数据）。
        if (scorer.hasAnyContext(text, start, end, NEGATIVE_CONTEXT)) {
            return null;
        }
        if (!inRange) {
            return null;
        }
        if (contextRequired) {
            return null;
        }
        return new RuleMatch(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX, GuardRiskLevel.MEDIUM,
                0.5, start, end, RULE_ID, "valid secp256k1 range, no context");
    }

    private static boolean isValidCurveKey(String text, int start, int end) {
        String token = text.substring(start, end);
        String hex = token.regionMatches(true, 0, "0x", 0, 2) ? token.substring(2) : token;
        try {
            return Secp256k1Range.isValidPrivateKey(new BigInteger(hex, 16));
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean isCovered(int start, List<int[]> covered) {
        for (int[] span : covered) {
            if (start >= span[0] && start < span[1]) {
                return true;
            }
        }
        return false;
    }
}
