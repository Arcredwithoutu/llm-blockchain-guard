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
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Solana keypair（id.json 字节数组）检测规则：JSON int 数组长度 64、元素 0–255。
 * <ul>
 *   <li>命中 {@code solana/keypair/id.json/fromSecretKey/secretKey} 上下文 → CRITICAL</li>
 *   <li>纯 64 长度字节数组、无上下文 → MEDIUM（形态可疑但弱信号）</li>
 * </ul>
 *
 * <p>不做完整 JSON 反序列化（core 零 Gson），按 {@code [..]} 形态正则提取后逐元素校验。</p>
 */
public final class SolanaKeypairRule implements DetectionRule {

    private static final String RULE_ID = "solana-keypair";
    private static final int KEYPAIR_LEN = 64;
    private static final int MAX_BYTE = 255;
    // 形如 [12,34,...] 的字节数组（允许空白）。正则 {10,} 只做「形态粗筛」（足够长的数字数组），
    // 恰 64 个元素 + 每个 0–255 的精确判定由 isLen64ByteArray 完成。
    private static final Pattern BYTE_ARRAY = Pattern.compile("\\[\\s*\\d{1,3}(?:\\s*,\\s*\\d{1,3}){10,}\\s*]");
    private static final List<String> CONTEXT = List.of(
            "solana", "keypair", "id.json", "fromsecretkey", "secretkey", "secret key");
    private static final ContextWindowScorer SCORER = new ContextWindowScorer(64);

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
        Matcher matcher = BYTE_ARRAY.matcher(text);
        while (matcher.find()) {
            if (!isLen64ByteArray(matcher.group())) {
                continue;
            }
            int start = matcher.start();
            int end = matcher.end();
            if (SCORER.hasAnyContext(text, start, end, CONTEXT)) {
                matches.add(new RuleMatch(GuardEntityType.BLOCKCHAIN_SOLANA_KEYPAIR, GuardRiskLevel.CRITICAL,
                        0.95, start, end, RULE_ID, "Solana keypair byte array with context"));
            } else {
                matches.add(new RuleMatch(GuardEntityType.BLOCKCHAIN_SOLANA_KEYPAIR, GuardRiskLevel.MEDIUM,
                        0.4, start, end, RULE_ID, "64-length byte array, no context"));
            }
        }
        return matches;
    }

    /** 解析逗号分隔的整数：恰 64 个、每个 0–255。 */
    private static boolean isLen64ByteArray(String token) {
        String inner = token.substring(1, token.length() - 1).trim();
        String[] parts = inner.split(",");
        if (parts.length != KEYPAIR_LEN) {
            return false;
        }
        for (String part : parts) {
            try {
                int value = Integer.parseInt(part.trim());
                if (value < 0 || value > MAX_BYTE) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }
}
