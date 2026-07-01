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
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cardano signing key（{@code .skey}）检测规则：JSON {@code type} 值含 {@code SigningKey}
 * （如 {@code PaymentSigningKeyShelley_ed25519} / {@code StakeSigningKeyShelley_ed25519} /
 * {@code PaymentExtendedSigningKeyShelley_ed25519_bip32}）且含 {@code cborHex} 键 → CRITICAL。
 *
 * <p>不做完整 JSON 反序列化（core 零 Gson），按键值正则判定结构特征。</p>
 */
public final class CardanoSigningKeyRule implements DetectionRule {

    private static final String RULE_ID = "cardano-signing-key";
    // type 值含 SigningKey（覆盖 Payment/Stake/PaymentExtended/Genesis... 各 Shelley 变体）。
    private static final Pattern SIGNING_KEY_TYPE =
            Pattern.compile("(?i)\"type\"\\s*:\\s*\"[A-Za-z0-9_]*SigningKey[A-Za-z0-9_]*\"");
    private static final Pattern CBOR_HEX = Pattern.compile("(?i)\"cborHex\"\\s*:");

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<RuleMatch> detect(String text, GuardContext ctx) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        // type 与 cborHex 各用全文 find()、未限定同一对象内：故意保守（宁误报勿漏检），
        // 结构化精确定位（确认两键同属一个 .skey 对象）推迟到批次三红队。
        Matcher type = SIGNING_KEY_TYPE.matcher(text);
        if (!type.find() || !CBOR_HEX.matcher(text).find()) {
            return List.of();
        }
        int start = text.indexOf('{');
        int end = text.lastIndexOf('}');
        if (start < 0 || end < start) {
            start = type.start();
            end = text.length();
        } else {
            end += 1;
        }
        return List.of(new RuleMatch(GuardEntityType.BLOCKCHAIN_CARDANO_SIGNING_KEY, GuardRiskLevel.CRITICAL,
                0.97, start, end, RULE_ID, "Cardano signing key (.skey type+cborHex)"));
    }
}
