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
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class SpanMergerTest {

    @Test
    void sortsByStartAscEndDesc() {
        GuardFinding later = finding(GuardEntityType.PII, GuardRiskLevel.MEDIUM, 5, 9);
        GuardFinding earlierLong = finding(GuardEntityType.API_KEY, GuardRiskLevel.HIGH, 2, 8);
        GuardFinding earlierShort = finding(GuardEntityType.API_KEY, GuardRiskLevel.HIGH, 2, 4);
        List<GuardFinding> merged = SpanMerger.merge(List.of(later, earlierShort, earlierLong));
        // 2..8 覆盖 2..4，应合并；5..9 与 2..8 重叠也应合并为单 span。
        assertThat(merged).hasSize(1);
        assertThat(merged.get(0).start()).isEqualTo(2);
        assertThat(merged.get(0).end()).isEqualTo(9);
    }

    @Test
    void keepsHigherRiskOnOverlap() {
        GuardFinding low = finding(GuardEntityType.BLOCKCHAIN_ADDRESS, GuardRiskLevel.LOW, 0, 10);
        GuardFinding critical = finding(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX, GuardRiskLevel.CRITICAL, 3, 12);
        List<GuardFinding> merged = SpanMerger.merge(List.of(low, critical));
        assertThat(merged).hasSize(1);
        assertThat(merged.get(0).riskLevel()).isEqualTo(GuardRiskLevel.CRITICAL);
        assertThat(merged.get(0).entityType()).isEqualTo(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX);
        assertThat(merged.get(0).start()).isEqualTo(0);
        assertThat(merged.get(0).end()).isEqualTo(12);
    }

    @Test
    void keepsDisjointSpansSeparate() {
        GuardFinding a = finding(GuardEntityType.API_KEY, GuardRiskLevel.HIGH, 0, 4);
        GuardFinding b = finding(GuardEntityType.API_KEY, GuardRiskLevel.HIGH, 6, 10);
        List<GuardFinding> merged = SpanMerger.merge(List.of(a, b));
        assertThat(merged).hasSize(2);
    }

    @Test
    void emptyInputReturnsEmpty() {
        assertThat(SpanMerger.merge(List.of())).isEmpty();
    }

    @Test
    void mergeWithinTypeKeepsDifferentEntityTypesSeparate() {
        GuardFinding injection = finding(GuardEntityType.PROMPT_INJECTION, GuardRiskLevel.HIGH, 0, 30);
        GuardFinding credential = finding(GuardEntityType.API_KEY, GuardRiskLevel.HIGH, 5, 15);
        List<GuardFinding> merged = SpanMerger.mergeWithinType(List.of(injection, credential));
        // 跨 entityType 的重叠不合并，二者各自保留。
        assertThat(merged).hasSize(2);
        assertThat(merged).extracting(GuardFinding::entityType)
                .containsExactlyInAnyOrder(GuardEntityType.PROMPT_INJECTION, GuardEntityType.API_KEY);
    }

    @Test
    void mergeWithinTypeStillMergesSameTypeOverlap() {
        GuardFinding a = finding(GuardEntityType.PII, GuardRiskLevel.MEDIUM, 0, 10);
        GuardFinding b = finding(GuardEntityType.PII, GuardRiskLevel.MEDIUM, 5, 15);
        List<GuardFinding> merged = SpanMerger.mergeWithinType(List.of(a, b));
        // 同类型重叠仍合并为并集 span。
        assertThat(merged).hasSize(1);
        assertThat(merged.get(0).start()).isEqualTo(0);
        assertThat(merged.get(0).end()).isEqualTo(15);
    }

    private static GuardFinding finding(GuardEntityType type, GuardRiskLevel risk, int start, int end) {
        return new GuardFinding(type, risk, 0.9, start, end, "rule", "reason", null);
    }
}
