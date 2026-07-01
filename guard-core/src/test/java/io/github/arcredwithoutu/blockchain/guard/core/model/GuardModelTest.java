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

package io.github.arcredwithoutu.blockchain.guard.core.model;

import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import static org.assertj.core.api.Assertions.assertThat;

class GuardModelTest {

    @Test
    void blockedReflectsAction() {
        GuardDecision blocked = new GuardDecision(GuardAction.BLOCK, "", List.of(), "msg", 3);
        GuardDecision allowed = new GuardDecision(GuardAction.ALLOW, "x", List.of(), null, 1);
        assertThat(blocked.blocked()).isTrue();
        assertThat(allowed.blocked()).isFalse();
    }

    @Test
    void userInputFactoryFillsDirection() {
        GuardContext ctx = GuardContext.userInput("rag-chat", "trace-1", "conv-1", "user-1");
        assertThat(ctx.direction()).isEqualTo(GuardDirection.USER_INPUT);
        assertThat(ctx.traceId()).isEqualTo("trace-1");
        assertThat(ctx.attributes()).isEqualTo(Map.of());
    }

    @Test
    void findingKeepsSpan() {
        GuardFinding f = new GuardFinding(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX,
                GuardRiskLevel.CRITICAL, 0.99, 10, 74, "evm-hex", "ctx+curve", "ab12cd34");
        assertThat(f.end() - f.start()).isEqualTo(64);
        assertThat(f.riskLevel()).isEqualTo(GuardRiskLevel.CRITICAL);
    }
}
