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

package io.github.arcredwithoutu.blockchain.guard.core.scanner;

import io.github.arcredwithoutu.blockchain.guard.core.api.GuardScanner;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.AddressClassifier;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 链上公开标识扫描器（设计 §14.1）：把 {@link AddressClassifier} 接入扫描链，识别 EVM 地址 / tx hash /
 * base58 比特币地址，产出 LOW 风险的 {@link GuardEntityType#BLOCKCHAIN_ADDRESS} /
 * {@link GuardEntityType#BLOCKCHAIN_TX_HASH} finding（公开非密材料，策略流转放行、落库部分掩码）。
 *
 * <p>仅做形态识别、不做上下文判定；候选 token 由正则在全文 find，再交 {@link AddressClassifier#classify}
 * 定型（复用同一套形态规则）。64hex 私钥与 tx hash 的区分由 {@code EvmPrivateKeyHexRule} 的上下文逻辑负责：
 * 负向上下文（tx_hash/sha256…）下私钥规则不出 finding，{@code 0x}+64hex 由本扫描器识别为 TX_HASH；
 * 真私钥（正向上下文/曲线范围）仍由私钥规则判 CRITICAL/HIGH 并优先阻断。</p>
 */
public final class BlockchainAddressScanner implements GuardScanner {

    private static final String NAME = "blockchain-address";
    private static final double CONFIDENCE = 0.95;
    private static final String RULE_ADDRESS = "blockchain-address";
    private static final String RULE_TX_HASH = "blockchain-tx-hash";

    // 0x + 40/64 hex（前界非字母数字、后界非 hex，避免吃进更长 hex 串或截断 64hex）。
    private static final Pattern EVM_CANDIDATE =
            Pattern.compile("(?<![0-9A-Za-z])0x[0-9a-fA-F]{40,64}(?![0-9a-fA-F])");
    // base58 比特币地址（'1'/'3' 前缀，长度 26~35），前后界排除 base58 字符避免截取更长串。
    private static final Pattern BTC_CANDIDATE =
            Pattern.compile("(?<![1-9A-HJ-NP-Za-km-z])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![1-9A-HJ-NP-Za-km-z])");

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean supports(GuardContext ctx) {
        return true;
    }

    @Override
    public List<GuardFinding> scan(String text, GuardContext ctx) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        List<GuardFinding> findings = new ArrayList<>();
        collect(text, EVM_CANDIDATE, findings);
        collect(text, BTC_CANDIDATE, findings);
        return findings;
    }

    private static void collect(String text, Pattern pattern, List<GuardFinding> findings) {
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            GuardEntityType type = AddressClassifier.classify(matcher.group());
            if (type == null) {
                continue;
            }
            String ruleId = type == GuardEntityType.BLOCKCHAIN_TX_HASH ? RULE_TX_HASH : RULE_ADDRESS;
            findings.add(new GuardFinding(type, GuardRiskLevel.LOW, CONFIDENCE,
                    matcher.start(), matcher.end(), ruleId, "address classifier matched " + type.name(), null));
        }
    }
}
