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

import static org.assertj.core.api.Assertions.assertThat;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import io.github.arcredwithoutu.blockchain.guard.core.provider.GuardProviderClient;
import io.github.arcredwithoutu.blockchain.guard.core.provider.ProviderEntity;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * provider PII 扫描器单测：注入 stub {@link GuardProviderClient} 返回假实体，不依赖真 Presidio sidecar。
 * 覆盖映射、min-score 过滤、span 校验、开关门控、降级。测试文本为合成 PII，无任何真实私钥/敏感信息。
 */
class ProviderPiiScannerTest {

    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");

    @Test
    void mapsProviderEntitiesToPiiFindings() {
        GuardProviderClient stub = text -> List.of(
                new ProviderEntity("EMAIL_ADDRESS", 5, 20, 0.85),
                new ProviderEntity("PERSON", 0, 4, 0.6));
        ProviderPiiScanner scanner = new ProviderPiiScanner(stub, true, 0.5);

        List<GuardFinding> findings = scanner.scan("Bob: alice@example.com", ctx);

        assertThat(findings).hasSize(2);
        assertThat(findings).allMatch(f -> f.entityType() == GuardEntityType.PII);
        assertThat(findings).anyMatch(f -> f.ruleId().equals("pii-presidio:EMAIL_ADDRESS")
                && f.start() == 5 && f.end() == 20 && f.confidence() == 0.85);
    }

    @Test
    void filtersOutEntitiesBelowMinScore() {
        GuardProviderClient stub = text -> List.of(
                new ProviderEntity("PERSON", 0, 4, 0.30),
                new ProviderEntity("EMAIL_ADDRESS", 5, 20, 0.90));
        ProviderPiiScanner scanner = new ProviderPiiScanner(stub, true, 0.5);

        List<GuardFinding> findings = scanner.scan("Bob: alice@example.com", ctx);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("pii-presidio:EMAIL_ADDRESS");
    }

    @Test
    void skipsEntitiesWithoutValidSpan() {
        // start=-1（provider 未给 span）与 end<=start 均无法定位/脱敏，跳过。
        GuardProviderClient stub = text -> List.of(
                new ProviderEntity("PERSON", -1, -1, 0.9),
                new ProviderEntity("EMAIL_ADDRESS", 5, 5, 0.9));
        ProviderPiiScanner scanner = new ProviderPiiScanner(stub, true, 0.5);

        assertThat(scanner.scan("Bob: alice@example.com", ctx)).isEmpty();
    }

    @Test
    void disabledScannerDoesNotSupportAndReturnsEmpty() {
        GuardProviderClient stub = text -> List.of(new ProviderEntity("PERSON", 0, 3, 0.9));
        ProviderPiiScanner scanner = new ProviderPiiScanner(stub, false, 0.5);

        assertThat(scanner.supports(ctx)).isFalse();
        assertThat(scanner.scan("Bob", ctx)).isEmpty();
    }

    @Test
    void degradesWhenClientReturnsEmpty() {
        // client 超时/异常时按契约返回空列表 → 扫描器无命中、不抛。
        GuardProviderClient stub = text -> List.of();
        ProviderPiiScanner scanner = new ProviderPiiScanner(stub, true, 0.5);

        assertThat(scanner.scan("Bob: alice@example.com", ctx)).isEmpty();
    }

    @Test
    void filtersOutTypesNotInAllowList() {
        // DATE_TIME 等贪婪类型不在白名单 → 过滤；白名单内类型（EMAIL_ADDRESS）保留。
        GuardProviderClient stub = text -> List.of(
                new ProviderEntity("DATE_TIME", 0, 4, 0.95),
                new ProviderEntity("EMAIL_ADDRESS", 5, 20, 0.90));
        ProviderPiiScanner scanner = new ProviderPiiScanner(stub, true, 0.5,
                Set.of("EMAIL_ADDRESS", "PERSON"));

        List<GuardFinding> findings = scanner.scan("week alice@example.com", ctx);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("pii-presidio:EMAIL_ADDRESS");
    }

    @Test
    void keepsAllowedTypes() {
        GuardProviderClient stub = text -> List.of(
                new ProviderEntity("PERSON", 0, 3, 0.9),
                new ProviderEntity("EMAIL_ADDRESS", 5, 20, 0.9));
        ProviderPiiScanner scanner = new ProviderPiiScanner(stub, true, 0.5,
                Set.of("PERSON", "EMAIL_ADDRESS"));

        assertThat(scanner.scan("Bob: alice@example.com", ctx)).hasSize(2);
    }

    @Test
    void doesNotFilterWhenAllowedTypesNullOrEmpty() {
        // allowedTypes 为 null（兼容旧 3 参构造）/空集合时来者不拒，行为与历史一致。
        GuardProviderClient stub = text -> List.of(
                new ProviderEntity("DATE_TIME", 0, 4, 0.95),
                new ProviderEntity("EMAIL_ADDRESS", 5, 20, 0.90));

        assertThat(new ProviderPiiScanner(stub, true, 0.5).scan("week alice@example.com", ctx)).hasSize(2);
        assertThat(new ProviderPiiScanner(stub, true, 0.5, Set.of())
                .scan("week alice@example.com", ctx)).hasSize(2);
    }

    @Test
    void assignsHighRiskToSensitiveTypesAndMediumToOthers() {
        // 高敏类型（CREDIT_CARD）赋 HIGH；其余（PERSON）维持 MEDIUM；entityType 仍统一为 PII。
        GuardProviderClient stub = text -> List.of(
                new ProviderEntity("CREDIT_CARD", 0, 16, 0.95),
                new ProviderEntity("PERSON", 17, 20, 0.8));
        ProviderPiiScanner scanner = new ProviderPiiScanner(stub, true, 0.5, null);

        List<GuardFinding> findings = scanner.scan("4111111111111111 Bob", ctx);

        assertThat(findings).hasSize(2);
        assertThat(findings).allMatch(f -> f.entityType() == GuardEntityType.PII);
        assertThat(findings).anyMatch(f -> f.ruleId().equals("pii-presidio:CREDIT_CARD")
                && f.riskLevel() == GuardRiskLevel.HIGH);
        assertThat(findings).anyMatch(f -> f.ruleId().equals("pii-presidio:PERSON")
                && f.riskLevel() == GuardRiskLevel.MEDIUM);
    }
}
