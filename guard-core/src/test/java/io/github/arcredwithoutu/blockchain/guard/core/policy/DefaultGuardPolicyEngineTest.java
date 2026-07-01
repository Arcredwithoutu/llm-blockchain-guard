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

package io.github.arcredwithoutu.blockchain.guard.core.policy;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardAction;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardDirection;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.assertj.core.api.Assertions.assertThat;

class DefaultGuardPolicyEngineTest {
    private final DefaultGuardPolicyEngine engine = new DefaultGuardPolicyEngine(GuardPolicyConfig.defaults());

    @Test
    void privateKeyAlwaysBlocked() {
        for (GuardDirection d : GuardDirection.values()) {
            assertThat(engine.decide(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX, d, GuardRiskLevel.CRITICAL, 0.99))
                    .isEqualTo(GuardAction.BLOCK);
        }
    }

    @Test
    void addressAllowedForModelInput() {
        assertThat(engine.decide(GuardEntityType.BLOCKCHAIN_ADDRESS, GuardDirection.MODEL_INPUT, GuardRiskLevel.LOW, 0.9))
                .isEqualTo(GuardAction.ALLOW);
    }

    @Test
    void addressMaskedForPersist() {
        assertThat(engine.decide(GuardEntityType.BLOCKCHAIN_ADDRESS, GuardDirection.TRACE_PERSIST, GuardRiskLevel.LOW, 0.9))
                .isEqualTo(GuardAction.MASK);
    }

    @Test
    void piiMaskedEverywhere() {
        assertThat(engine.decide(GuardEntityType.PII, GuardDirection.MEMORY_PERSIST, GuardRiskLevel.MEDIUM, 0.9))
                .isEqualTo(GuardAction.MASK);
    }

    /** 即便 config 把私钥行放宽为 ALLOW，CRITICAL 私钥类硬规则仍凌驾 config、所有方向 BLOCK（§7）。 */
    @Test
    void criticalPrivateKeyBlockedEvenWhenConfigRelaxed() {
        GuardPolicyConfig relaxed = new GuardPolicyConfig(
                Map.of(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX, DirectionPolicy.uniform(GuardAction.ALLOW)),
                GuardAction.ALLOW);
        DefaultGuardPolicyEngine relaxedEngine = new DefaultGuardPolicyEngine(relaxed);
        for (GuardDirection d : GuardDirection.values()) {
            assertThat(relaxedEngine.decide(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX, d, GuardRiskLevel.CRITICAL, 0.99))
                    .isEqualTo(GuardAction.BLOCK);
        }
    }
}
