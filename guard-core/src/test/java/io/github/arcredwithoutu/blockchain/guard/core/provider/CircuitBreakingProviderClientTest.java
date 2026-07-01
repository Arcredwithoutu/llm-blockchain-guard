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

package io.github.arcredwithoutu.blockchain.guard.core.provider;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/**
 * 熔断装饰器单测：注入可控时钟 + 可控耗时 stub delegate，验证慢调用计失败、连续失败开熔断短路、
 * 冷却窗后放行试探、快调用不触发熔断。不依赖真实时间/网络。
 */
class CircuitBreakingProviderClientTest {

    private static final long SLOW = 300L;
    private static final long COOLDOWN = 1000L;

    @Test
    void opensAfterConsecutiveSlowCallsThenShortCircuits() {
        AtomicLong now = new AtomicLong(0);
        int[] delegateCalls = {0};
        GuardProviderClient slowDelegate = text -> {
            delegateCalls[0]++;
            now.addAndGet(SLOW); // 模拟耗时命中超时
            return List.of();
        };
        CircuitBreakingProviderClient cb =
                new CircuitBreakingProviderClient(slowDelegate, 2, SLOW, COOLDOWN, now::get);

        cb.analyze("x"); // 慢调用 1
        cb.analyze("x"); // 慢调用 2 → 达阈值开熔断
        int callsBeforeShortCircuit = delegateCalls[0];
        cb.analyze("x"); // 冷却窗内 → 短路，不打 delegate

        assertThat(delegateCalls[0]).isEqualTo(callsBeforeShortCircuit);
    }

    @Test
    void probesAgainAfterCooldown() {
        AtomicLong now = new AtomicLong(0);
        int[] delegateCalls = {0};
        GuardProviderClient slowDelegate = text -> {
            delegateCalls[0]++;
            now.addAndGet(SLOW);
            return List.of();
        };
        CircuitBreakingProviderClient cb =
                new CircuitBreakingProviderClient(slowDelegate, 1, SLOW, COOLDOWN, now::get);

        cb.analyze("x"); // 阈值 1，1 次慢调用即开熔断
        int afterOpen = delegateCalls[0];
        cb.analyze("x"); // 冷却窗内短路
        assertThat(delegateCalls[0]).isEqualTo(afterOpen);

        now.addAndGet(2 * COOLDOWN); // 推进超过冷却窗
        cb.analyze("x"); // 放行试探

        assertThat(delegateCalls[0]).isEqualTo(afterOpen + 1);
    }

    @Test
    void fastCallsKeepCircuitClosed() {
        AtomicLong now = new AtomicLong(0);
        int[] delegateCalls = {0};
        GuardProviderClient fastDelegate = text -> {
            delegateCalls[0]++;
            now.addAndGet(10); // 快调用，远小于 SLOW 阈值
            return List.of(new ProviderEntity("PERSON", 0, 3, 0.9));
        };
        CircuitBreakingProviderClient cb =
                new CircuitBreakingProviderClient(fastDelegate, 2, SLOW, COOLDOWN, now::get);

        for (int i = 0; i < 5; i++) {
            assertThat(cb.analyze("x")).hasSize(1); // 始终放行，从不短路
        }
        assertThat(delegateCalls[0]).isEqualTo(5);
    }
}
