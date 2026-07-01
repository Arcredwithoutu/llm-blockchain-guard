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
 * PEM 私钥检测规则：命中 {@code -----BEGIN [EC|OPENSSH|RSA ]PRIVATE KEY-----} 头即判 CRITICAL。
 * span 取 BEGIN 头到对应 END 尾（若有），否则仅 BEGIN 头——头本身已是确定性 secret 标记。
 */
public final class PemPrivateKeyRule implements DetectionRule {

    private static final String RULE_ID = "pem-private-key";
    // BIP173 风格宽松配对：BEGIN 头允许任意私钥类型，END 尾可选（缺尾仍判，头即强信号）。
    private static final Pattern PEM = Pattern.compile(
            "-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
                    + "(?:[\\s\\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----)?");

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
        Matcher matcher = PEM.matcher(text);
        while (matcher.find()) {
            matches.add(new RuleMatch(GuardEntityType.PEM_PRIVATE_KEY, GuardRiskLevel.CRITICAL,
                    0.99, matcher.start(), matcher.end(), RULE_ID, "PEM private key block"));
        }
        return matches;
    }
}
