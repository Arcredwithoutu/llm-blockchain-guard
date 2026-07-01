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
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 命中 span 合并器（设计 §5.1）：按 {@code start asc, end desc} 排序后合并重叠 span，
 * 重叠时保留较高风险的 finding 元数据，span 取并集。
 */
public final class SpanMerger {

    private static final Comparator<GuardFinding> ORDER =
            Comparator.comparingInt(GuardFinding::start)
                    .thenComparing(Comparator.comparingInt(GuardFinding::end).reversed());

    private SpanMerger() {
    }

    /** 合并重叠 span：重叠（严格 {@code next.start < current.end}）合并，保留高风险元数据与并集 span。 */
    public static List<GuardFinding> merge(List<GuardFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            return List.of();
        }
        List<GuardFinding> sorted = new ArrayList<>(findings);
        sorted.sort(ORDER);
        List<GuardFinding> merged = new ArrayList<>();
        GuardFinding current = sorted.get(0);
        for (int i = 1; i < sorted.size(); i++) {
            GuardFinding next = sorted.get(i);
            if (next.start() < current.end()) {
                current = combine(current, next);
            } else {
                merged.add(current);
                current = next;
            }
        }
        merged.add(current);
        return merged;
    }

    /**
     * 按 {@link GuardEntityType} 分组后各自 {@link #merge}：同类型重叠（真重复，如本地与 provider 命中同一
     * email）合并去重，<b>不同 entityType 的重叠保留为独立 finding</b>（它们是不同安全关切，不应相互吞并）。
     *
     * <p>用于决策与审计：避免「整段注入命中」吞并同句凭据/PII 而把本应 BLOCK 的凭据降级、把审计计数塌缩。
     * 掩码仍走 {@link #merge} 做全合并（masker 内部自行调用），以保证替换区间不重叠。</p>
     */
    public static List<GuardFinding> mergeWithinType(List<GuardFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            return List.of();
        }
        Map<GuardEntityType, List<GuardFinding>> byType = new LinkedHashMap<>();
        for (GuardFinding finding : findings) {
            byType.computeIfAbsent(finding.entityType(), key -> new ArrayList<>()).add(finding);
        }
        List<GuardFinding> result = new ArrayList<>();
        for (List<GuardFinding> group : byType.values()) {
            result.addAll(merge(group));
        }
        return result;
    }

    /** 取并集 span，元数据沿用较高风险的一方（风险相同则保留先到的 base）。 */
    private static GuardFinding combine(GuardFinding base, GuardFinding other) {
        int start = Math.min(base.start(), other.start());
        int end = Math.max(base.end(), other.end());
        GuardFinding winner = other.riskLevel().ordinal() > base.riskLevel().ordinal() ? other : base;
        return new GuardFinding(winner.entityType(), winner.riskLevel(), winner.confidence(),
                start, end, winner.ruleId(), winner.reason(), winner.fingerprint());
    }
}
