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

package io.github.arcredwithoutu.blockchain.guard.core.mask;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * 脱敏掩码器（设计 §5.1）：合并 span → 从后往前替换（避免 offset 漂移）→ 按 entityType 选替换格式。
 *
 * <ul>
 *   <li>私钥/助记词/keystore/PEM → {@code [BLOCKCHAIN_SECRET:<ENTITY>:<fp8>]}</li>
 *   <li>API Key/password/JWT → {@code [SECRET:<ENTITY>:<fp8>]}</li>
 *   <li>地址/tx hash → 保留前后（{@code 0x1234...abcd}）</li>
 *   <li>PII → {@code [PII:<TYPE>]}</li>
 *   <li>prompt injection → {@code [REMOVED_UNTRUSTED_INSTRUCTION]}</li>
 * </ul>
 *
 * <p>CRITICAL 替换串不含原文任何片段；fingerprint 由 {@link FingerprintService#fingerprint8} 对原文 secret 子串现算。</p>
 */
public final class GuardMasker {

    private static final int ADDRESS_HEAD = 6;
    private static final int ADDRESS_TAIL = 4;
    private static final String INJECTION_MARKER = "[REMOVED_UNTRUSTED_INSTRUCTION]";

    private final FingerprintService fingerprintService;

    public GuardMasker(FingerprintService fingerprintService) {
        this.fingerprintService = Objects.requireNonNull(fingerprintService, "fingerprintService");
    }

    /** 合并 span 后从后往前替换；无命中返回原文。 */
    public String apply(String text, List<GuardFinding> findings) {
        if (text == null || text.isEmpty() || findings == null || findings.isEmpty()) {
            return text;
        }
        List<GuardFinding> merged = SpanMerger.merge(findings);
        List<ReplacementPlan> plans = new ArrayList<>(merged.size());
        for (GuardFinding finding : merged) {
            int start = Math.max(0, finding.start());
            int end = Math.min(text.length(), finding.end());
            if (start >= end) {
                continue;
            }
            String raw = text.substring(start, end);
            plans.add(new ReplacementPlan(start, end, replacementFor(finding, raw)));
        }
        // 从后往前替换，避免前面替换改变后面 span 的偏移。
        StringBuilder sb = new StringBuilder(text);
        for (int i = plans.size() - 1; i >= 0; i--) {
            ReplacementPlan plan = plans.get(i);
            sb.replace(plan.start(), plan.end(), plan.replacement());
        }
        return sb.toString();
    }

    private String replacementFor(GuardFinding finding, String raw) {
        GuardEntityType type = finding.entityType();
        return switch (type) {
            case BLOCKCHAIN_ADDRESS, BLOCKCHAIN_TX_HASH -> partialMask(raw);
            case PII -> "[PII:" + piiSubtype(finding.ruleId()) + "]";
            case PROMPT_INJECTION -> INJECTION_MARKER;
            case API_KEY, PASSWORD, JWT -> "[SECRET:" + type.name() + ":" + fingerprintService.fingerprint8(raw) + "]";
            default -> "[BLOCKCHAIN_SECRET:" + type.name() + ":" + fingerprintService.fingerprint8(raw) + "]";
        };
    }

    /** PII 子类标签：本地规则映射固定子类，远程 pii-presidio:X 透传 X，未知/空回落 PII（兜底不泄漏原文）。 */
    private static String piiSubtype(String ruleId) {
        if (ruleId == null) {
            return "PII";
        }
        if (ruleId.startsWith("pii-presidio:")) {
            String providerType = ruleId.substring("pii-presidio:".length());
            return providerType.isBlank() ? "PII" : providerType;
        }
        return switch (ruleId) {
            case "pii-email" -> "EMAIL";
            case "pii-cn-phone" -> "PHONE";
            case "pii-cn-id-card" -> "ID_CARD";
            case "pii-bank-card" -> "BANK_CARD";
            default -> "PII";
        };
    }

    /** 地址/tx hash 保留前 {@value ADDRESS_HEAD} + 后 {@value ADDRESS_TAIL} 字符，中间以 {@code ...} 省略。 */
    private static String partialMask(String raw) {
        if (raw.length() <= ADDRESS_HEAD + ADDRESS_TAIL) {
            return raw;
        }
        return raw.substring(0, ADDRESS_HEAD) + "..." + raw.substring(raw.length() - ADDRESS_TAIL);
    }
}
