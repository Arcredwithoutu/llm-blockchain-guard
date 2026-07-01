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
 * Substrate Secret URI（SURI）检测规则。命中两类形态：
 * <ul>
 *   <li>SURI 派生语法：基础密钥 + {@code //hard}/{@code /soft}/{@code ///password} 派生结（含 {@code //} 硬派生即判）</li>
 *   <li>{@code 0x}+64hex raw seed，且窗口含 {@code sr25519/ed25519/substrate/suri} 上下文</li>
 * </ul>
 * 命中 → CRITICAL。
 */
public final class SubstrateSecretUriRule implements DetectionRule {

    private static final String RULE_ID = "substrate-secret-uri";
    // 基础密钥（助记词词串或 0x seed）后跟至少一个 //硬派生 或 ///password 结。
    // 形态锚点为 "//"（硬派生）——普通路径很少含双斜杠，作强信号。
    private static final Pattern SURI = Pattern.compile(
            "(?:0x[0-9a-fA-F]{64}|[a-z]+(?: [a-z]+){11,23})(?://+[^\\s/]+|///[^\\s]+)+");
    private static final Pattern RAW_SEED = Pattern.compile("0x[0-9a-fA-F]{64}");
    private static final List<String> CONTEXT = List.of("sr25519", "ed25519", "substrate", "suri", "polkadot");
    private static final ContextWindowScorer SCORER = new ContextWindowScorer(48);

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
        Matcher suri = SURI.matcher(text);
        while (suri.find()) {
            covered.add(new int[] {suri.start(), suri.end()});
            matches.add(new RuleMatch(GuardEntityType.BLOCKCHAIN_SUBSTRATE_SECRET_URI, GuardRiskLevel.CRITICAL,
                    0.95, suri.start(), suri.end(), RULE_ID, "Substrate secret URI with derivation path"));
        }
        Matcher seed = RAW_SEED.matcher(text);
        while (seed.find()) {
            if (isCovered(seed.start(), covered)) {
                continue;
            }
            if (SCORER.hasAnyContext(text, seed.start(), seed.end(), CONTEXT)) {
                matches.add(new RuleMatch(GuardEntityType.BLOCKCHAIN_SUBSTRATE_SECRET_URI, GuardRiskLevel.CRITICAL,
                        0.9, seed.start(), seed.end(), RULE_ID, "raw seed with substrate context"));
            }
        }
        return matches;
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
