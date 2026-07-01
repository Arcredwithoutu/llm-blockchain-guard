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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * BIP32/SLIP-0132 扩展密钥检测规则：Base58Check 解码后取前 4 字节 version 命中 SLIP-0132 表。
 * <ul>
 *   <li>{@code *prv}（私钥派生根）→ {@link GuardEntityType#BLOCKCHAIN_EXTENDED_PRIVATE_KEY} / CRITICAL</li>
 *   <li>{@code *pub}（暴露地址图谱，非花费私钥）→ {@link GuardEntityType#BLOCKCHAIN_EXTENDED_PUBLIC_KEY} / HIGH</li>
 * </ul>
 */
public final class ExtendedKeyRule implements DetectionRule {

    private static final String RULE_ID = "extended-key";
    // 扩展密钥固定 78 字节 payload，Base58Check 串长 111；放宽到 110~113 容错。
    private static final Pattern BASE58_TOKEN = Pattern.compile("[1-9A-HJ-NP-Za-km-z]{107,115}");

    /** SLIP-0132 version → 是否为私钥（true=prv/CRITICAL，false=pub/HIGH）。 */
    private static final Map<Integer, Boolean> VERSION_IS_PRIVATE = new HashMap<>();

    static {
        // xprv/xpub
        VERSION_IS_PRIVATE.put(0x0488ADE4, true);
        VERSION_IS_PRIVATE.put(0x0488B21E, false);
        // yprv/ypub
        VERSION_IS_PRIVATE.put(0x049D7878, true);
        VERSION_IS_PRIVATE.put(0x049D7CB2, false);
        // zprv/zpub
        VERSION_IS_PRIVATE.put(0x04B2430C, true);
        VERSION_IS_PRIVATE.put(0x04B24746, false);
        // tprv/tpub (testnet)
        VERSION_IS_PRIVATE.put(0x04358394, true);
        VERSION_IS_PRIVATE.put(0x043587CF, false);
        // uprv/upub
        VERSION_IS_PRIVATE.put(0x044A4E28, true);
        VERSION_IS_PRIVATE.put(0x044A5262, false);
        // vprv/vpub
        VERSION_IS_PRIVATE.put(0x045F18BC, true);
        VERSION_IS_PRIVATE.put(0x045F1CF6, false);
        // Yprv/Ypub
        VERSION_IS_PRIVATE.put(0x0295B005, true);
        VERSION_IS_PRIVATE.put(0x0295B43F, false);
        // Zprv/Zpub
        VERSION_IS_PRIVATE.put(0x02AA7A99, true);
        VERSION_IS_PRIVATE.put(0x02AA7ED3, false);
        // Uprv/Upub
        VERSION_IS_PRIVATE.put(0x024285B5, true);
        VERSION_IS_PRIVATE.put(0x024289EF, false);
        // Vprv/Vpub
        VERSION_IS_PRIVATE.put(0x02575048, true);
        VERSION_IS_PRIVATE.put(0x02575483, false);
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
        Matcher matcher = BASE58_TOKEN.matcher(text);
        while (matcher.find()) {
            RuleMatch match = evaluate(matcher.group(), matcher.start(), matcher.end());
            if (match != null) {
                matches.add(match);
            }
        }
        return matches;
    }

    private static RuleMatch evaluate(String token, int start, int end) {
        Optional<byte[]> decoded = Base58Check.decode(token);
        if (decoded.isEmpty() || decoded.get().length < 4) {
            return null;
        }
        byte[] payload = decoded.get();
        int version = ((payload[0] & 0xff) << 24) | ((payload[1] & 0xff) << 16)
                | ((payload[2] & 0xff) << 8) | (payload[3] & 0xff);
        Boolean isPrivate = VERSION_IS_PRIVATE.get(version);
        if (isPrivate == null) {
            return null;
        }
        if (isPrivate) {
            return new RuleMatch(GuardEntityType.BLOCKCHAIN_EXTENDED_PRIVATE_KEY, GuardRiskLevel.CRITICAL,
                    0.98, start, end, RULE_ID, "SLIP-0132 extended private key");
        }
        return new RuleMatch(GuardEntityType.BLOCKCHAIN_EXTENDED_PUBLIC_KEY, GuardRiskLevel.HIGH,
                0.85, start, end, RULE_ID, "SLIP-0132 extended public key (address graph exposure)");
    }
}
