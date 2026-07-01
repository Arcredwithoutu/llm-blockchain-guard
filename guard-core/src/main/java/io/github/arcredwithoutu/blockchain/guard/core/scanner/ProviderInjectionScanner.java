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

/**
 * 远程 provider prompt-injection 扫描器（设计 §10.2 步 8 / R3）：包 {@link GuardProviderClient}（LLM Guard），
 * 把 provider 的注入语义判定映射为 {@link GuardEntityType#PROMPT_INJECTION} 命中，与本地确定性
 * {@link PromptInjectionScanner} 并列注册，命中由下游 {@code SpanMerger} 合并去重。
 *
 * <p>与 {@link ProviderPiiScanner} 对称，但 injection 是整段判定：provider 通常不给精确 span（LLM Guard
 * 返回 start/end = -1），故无 span 时回退为整段 {@code [0, text.length())}，而非像 PII 那样丢弃。
 * provider 超时/异常由 client 内部降级为空列表，故 provider 不可用时本扫描器不产命中、不影响本地判定。</p>
 */
public final class ProviderInjectionScanner implements GuardScanner {

    private static final String NAME = "injection-provider";
    private static final String RULE_ID_PREFIX = "injection-llmguard:";

    private final GuardProviderClient client;
    private final boolean enabled;
    private final double minScore;

    /**
     * @param client   远程 provider 客户端（LLM Guard）；为 {@code null} 时本扫描器永不参与
     * @param enabled  是否启用（对应 {@code prompt-injection.provider-enabled}）
     * @param minScore 低分命中过滤阈值 [0,1]，低于此分丢弃（降误报）
     */
    public ProviderInjectionScanner(GuardProviderClient client, boolean enabled, double minScore) {
        this.client = client;
        this.enabled = enabled;
        this.minScore = minScore;
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
            // injection 整段判定：provider 未给 span（-1）时回退为整段覆盖；给了合法 span 则原样采用。
            int start = entity.start() >= 0 ? entity.start() : 0;
            int end = entity.end() > start ? Math.min(entity.end(), text.length()) : text.length();
            findings.add(new GuardFinding(GuardEntityType.PROMPT_INJECTION, GuardRiskLevel.HIGH, entity.score(),
                    start, end, RULE_ID_PREFIX + entity.type(), "provider injection " + entity.type(), null));
        }
        return findings;
    }
}
