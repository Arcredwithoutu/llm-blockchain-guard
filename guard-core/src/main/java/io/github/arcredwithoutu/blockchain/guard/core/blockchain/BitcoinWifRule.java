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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bitcoin WIF 私钥检测规则：Base58 串长 51/52 → Base58Check 解码校验 →
 * version {@code 0x80}(mainnet)/{@code 0xEF}(testnet)，payload 为 32B（uncompressed）
 * 或 33B 末位 {@code 0x01}（compressed）→ CRITICAL。
 */
public final class BitcoinWifRule implements DetectionRule {

    private static final String RULE_ID = "bitcoin-wif";
    // WIF Base58 串长 51（uncompressed）/52（compressed）。
    // 加 base58 负向环视边界，防与紧邻 base58 字符粘连导致取到偏移窗口、Base58Check 校验失败而漏检。
    private static final Pattern BASE58_TOKEN = Pattern.compile(
            "(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{51,52}(?![1-9A-HJ-NP-Za-km-z])");
    private static final int VERSION_MAINNET = 0x80;
    private static final int VERSION_TESTNET = 0xEF;
    private static final int KEY_LEN = 32;
    private static final int COMPRESSED_FLAG = 0x01;

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
        Matcher matcher = BASE58_TOKEN.matcher(text);
        while (matcher.find()) {
            if (isWif(matcher.group())) {
                matches.add(new RuleMatch(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_WIF, GuardRiskLevel.CRITICAL,
                        0.98, matcher.start(), matcher.end(), RULE_ID, "Bitcoin WIF private key"));
            }
        }
        return matches;
    }

    /** Base58Check 解码后 payload = version(1) + key(32) [+ compressed flag(1)]。 */
    private static boolean isWif(String token) {
        Optional<byte[]> decoded = Base58Check.decode(token);
        if (decoded.isEmpty()) {
            return false;
        }
        byte[] payload = decoded.get();
        if (payload.length != KEY_LEN + 1 && payload.length != KEY_LEN + 2) {
            return false;
        }
        int version = payload[0] & 0xff;
        if (version != VERSION_MAINNET && version != VERSION_TESTNET) {
            return false;
        }
        if (payload.length == KEY_LEN + 2 && (payload[payload.length - 1] & 0xff) != COMPRESSED_FLAG) {
            return false;
        }
        return true;
    }
}
