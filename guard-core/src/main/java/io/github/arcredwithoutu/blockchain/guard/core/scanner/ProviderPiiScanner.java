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
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import io.github.arcredwithoutu.blockchain.guard.core.provider.GuardProviderClient;
import io.github.arcredwithoutu.blockchain.guard.core.provider.ProviderEntity;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * 远程 provider PII 扫描器（方案 B，设计 §9.3 / R3）：包 {@link GuardProviderClient}（Presidio），把
 * {@link ProviderEntity} 语义命中映射为 {@link GuardFinding}，与本地确定性 {@link PiiScanner} 并列注册，
 * 命中由下游 {@code SpanMerger} 合并去重（同一 email/phone 双命中自动合并为一）。
 *
 * <p>provider 仅做 PII 语义增强；维护者已定调 Presidio 为系统内自托管受信组件，故用户原文直接外发做 PII
 * 分析——本处<strong>不</strong>对 secret 做脱密：本地 secret 由独立确定性 scanner 检出、交 policy 处置，
 * PII provider 不承担 secret 脱密职责。{@link GuardProviderClient} 超时/异常一律降级空列表，故 provider
 * 不可用时不影响本地确定性判定。低于 {@code minScore} 的低分猜测过滤以控误报；无有效 span（无法定位/
 * 脱敏）的命中跳过。</p>
 */
public final class ProviderPiiScanner implements GuardScanner {

    private static final String NAME = "pii-provider";
    private static final String RULE_ID_PREFIX = "pii-presidio:";

    /** 高敏实体类型：命中赋 {@link GuardRiskLevel#HIGH}，其余维持 MEDIUM（实体类型仍统一为 PII）。 */
    private static final Set<String> HIGH_RISK_TYPES = Set.of(
            "CREDIT_CARD", "US_SSN", "IBAN_CODE", "CN_USCC", "CN_PASSPORT", "US_PASSPORT", "MEDICAL_LICENSE");

    private final GuardProviderClient client;
    private final boolean enabled;
    private final double minScore;

    /** 实体类型白名单；{@code null}/空表示不过滤（保持向后兼容）。仅保留集合内类型的命中。 */
    private final Set<String> allowedTypes;

    /**
     * 向后兼容构造：不做类型白名单过滤（{@code allowedTypes = null}）。
     *
     * @param client   远程 provider 客户端（Presidio）；为 {@code null} 时本扫描器永不参与
     * @param enabled  是否启用（对应 {@code pii.provider.enabled}）
     * @param minScore 低分实体过滤阈值 [0,1]，低于此分的命中丢弃
     */
    public ProviderPiiScanner(GuardProviderClient client, boolean enabled, double minScore) {
        this(client, enabled, minScore, null);
    }

    /**
     * @param client       远程 provider 客户端（Presidio）；为 {@code null} 时本扫描器永不参与
     * @param enabled      是否启用（对应 {@code pii.provider.enabled}）
     * @param minScore     低分实体过滤阈值 [0,1]，低于此分的命中丢弃
     * @param allowedTypes 实体类型白名单；{@code null}/空表示不过滤（治理 DATE_TIME 等贪婪类型误报）
     */
    public ProviderPiiScanner(GuardProviderClient client, boolean enabled, double minScore, Set<String> allowedTypes) {
        this.client = client;
        this.enabled = enabled;
        this.minScore = minScore;
        this.allowedTypes = allowedTypes;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean supports(GuardContext ctx) {
        return enabled && client != null;
    }

    @Override
    public List<GuardFinding> scan(String text, GuardContext ctx) {
        if (!enabled || client == null || text == null || text.isEmpty()) {
            return List.of();
        }
        List<GuardFinding> findings = new ArrayList<>();
        for (ProviderEntity entity : client.analyze(text)) {
            if (entity.score() < minScore) {
                continue;
            }
            // 实体类型白名单过滤：剔除 DATE_TIME 等贪婪/低风险类型，仅保留真正 PII（白名单为空时不过滤）。
            if (allowedTypes != null && !allowedTypes.isEmpty() && !allowedTypes.contains(entity.type())) {
                continue;
            }
            // 无 span 或越界的命中无法定位/脱敏，跳过（provider 未给 span 时 start/end 为 -1）。
            if (entity.start() < 0 || entity.end() <= entity.start() || entity.end() > text.length()) {
                continue;
            }
            GuardRiskLevel riskLevel = HIGH_RISK_TYPES.contains(entity.type())
                    ? GuardRiskLevel.HIGH : GuardRiskLevel.MEDIUM;
            findings.add(new GuardFinding(GuardEntityType.PII, riskLevel, entity.score(),
                    entity.start(), entity.end(), RULE_ID_PREFIX + entity.type(),
                    "provider PII " + entity.type(), null));
        }
        return findings;
    }
}
