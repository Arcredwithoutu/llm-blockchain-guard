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
 * Web3 Secret Storage（keystore JSON / UTC--*）检测规则：JSON 含 {@code crypto} 对象的
 * {@code cipher/ciphertext/kdf/mac} 四键 + 顶层 {@code address} → CRITICAL（即使加密无密码也阻断）。
 *
 * <p>不做完整 JSON 反序列化（core 零 Gson），仅按键名出现的轻量正则判定结构特征。</p>
 */
public final class KeystoreJsonRule implements DetectionRule {

    private static final String RULE_ID = "keystore-json";
    // crypto/Crypto 键（geth 用小写、部分钱包用大写 Crypto）。
    private static final Pattern CRYPTO_KEY = Pattern.compile("(?i)\"crypto\"\\s*:");
    private static final Pattern CIPHER = Pattern.compile("(?i)\"cipher\"\\s*:");
    private static final Pattern CIPHERTEXT = Pattern.compile("(?i)\"ciphertext\"\\s*:");
    private static final Pattern KDF = Pattern.compile("(?i)\"kdf\"\\s*:");
    private static final Pattern MAC = Pattern.compile("(?i)\"mac\"\\s*:");
    private static final Pattern ADDRESS = Pattern.compile("(?i)\"address\"\\s*:");

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<RuleMatch> detect(String text, GuardContext ctx) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        Matcher crypto = CRYPTO_KEY.matcher(text);
        if (!crypto.find()) {
            return List.of();
        }
        // 子键用全文 find() 而非限定在 crypto 对象内：故意保守（宁误报勿漏检），
        // 结构化精确定位（确认 cipher/ciphertext/kdf/mac 同属一个 crypto 对象）推迟到批次三红队。
        boolean hasCryptoFields = CIPHER.matcher(text).find() && CIPHERTEXT.matcher(text).find()
                && KDF.matcher(text).find() && MAC.matcher(text).find();
        if (!hasCryptoFields || !ADDRESS.matcher(text).find()) {
            return List.of();
        }
        // span 覆盖整段 JSON（首个 '{' 到末个 '}'），mask 阶段保结构换值。
        int start = text.indexOf('{');
        int end = text.lastIndexOf('}');
        if (start < 0 || end < start) {
            start = crypto.start();
            end = text.length();
        } else {
            end += 1;
        }
        return List.of(new RuleMatch(GuardEntityType.BLOCKCHAIN_KEYSTORE_JSON, GuardRiskLevel.CRITICAL,
                0.97, start, end, RULE_ID, "Web3 keystore JSON (crypto+address)"));
    }
}
