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

import io.github.arcredwithoutu.blockchain.guard.core.codec.Bech32;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sui SIP-15 私钥检测规则：Bech32 解码 HRP={@code suiprivkey} →
 * {@code convertBits(data,5,8,false)} 得 33 字节 = flag(1)‖key(32)，flag ∈ {0x00..0x03} → CRITICAL。
 */
public final class SuiPrivateKeyRule implements DetectionRule {

    private static final String RULE_ID = "sui-privkey";
    private static final String HRP = "suiprivkey";
    // suiprivkey1 + 数据部分；按 bech32 字符集粗筛 token 边界。
    // 33 字节 payload → 53 个 5-bit 数据符 + 6 校验符 = 59；放宽 [55,65] 容错。
    private static final Pattern TOKEN = Pattern.compile("suiprivkey1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{55,65}");
    private static final int EXPECTED_LEN = 33;
    private static final int MAX_FLAG = 0x03;

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
        Matcher matcher = TOKEN.matcher(text);
        while (matcher.find()) {
            if (isSuiPrivateKey(matcher.group())) {
                matches.add(new RuleMatch(GuardEntityType.BLOCKCHAIN_SUI_PRIVKEY, GuardRiskLevel.CRITICAL,
                        0.98, matcher.start(), matcher.end(), RULE_ID, "Sui SIP-15 private key"));
            }
        }
        return matches;
    }

    private static boolean isSuiPrivateKey(String token) {
        Optional<Bech32.Decoded> decoded = Bech32.decode(token);
        if (decoded.isEmpty() || !HRP.equals(decoded.get().hrp())) {
            return false;
        }
        byte[] bytes = Bech32.convertBits(decoded.get().data(), 5, 8, false);
        if (bytes == null || bytes.length != EXPECTED_LEN) {
            return false;
        }
        int flag = bytes[0] & 0xff;
        return flag <= MAX_FLAG;
    }
}
