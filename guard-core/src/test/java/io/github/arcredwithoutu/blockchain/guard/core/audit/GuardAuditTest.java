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

package io.github.arcredwithoutu.blockchain.guard.core.audit;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardAction;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardDirection;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import org.junit.jupiter.api.Test;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class GuardAuditTest {

    /** GuardEvent 只可承载脱敏元数据，绝不含原文（无 rawText/secret/plainText/sanitizedText 字段）。 */
    @Test
    void guardEventHasNoRawTextField() {
        RecordComponent[] components = GuardEvent.class.getRecordComponents();
        assertThat(components).isNotNull();
        boolean carriesRaw = Arrays.stream(components)
                .map(RecordComponent::getName)
                .map(String::toLowerCase)
                .anyMatch(name -> name.contains("raw") || name.contains("secret")
                        || name.contains("plain") || name.contains("sanitized")
                        || name.contains("content") || name.equals("text"));
        assertThat(carriesRaw).isFalse();
        // fingerprint 字段必须存在（审计以 HMAC 指纹替代原文）。
        assertThat(Arrays.stream(components).map(RecordComponent::getName))
                .contains("fingerprint", "entityType", "action", "spanCount", "elapsedMs");
    }

    @Test
    void loggingSinkNeverThrows() {
        GuardAuditSink sink = new LoggingGuardAuditSink();
        GuardEvent event = new GuardEvent(GuardDirection.USER_INPUT, "rag-chat",
                GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX, GuardRiskLevel.CRITICAL, 0.99,
                GuardAction.BLOCK, "evm-hex", "ab12cd34", 1, 5L, "tr", "conv", "user", null);
        assertThatCode(() -> sink.record(event)).doesNotThrowAnyException();
        // null event 也不得抛异常（审计绝不能影响主链路）。
        assertThatCode(() -> sink.record(null)).doesNotThrowAnyException();
    }
}
