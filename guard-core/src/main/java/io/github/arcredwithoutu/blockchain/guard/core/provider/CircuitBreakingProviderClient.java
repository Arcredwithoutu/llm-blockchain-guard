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

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * provider 客户端熔断装饰器：包 {@link GuardProviderClient}，把「慢调用」（耗时 ≥ {@code slowCallMillis}，
 * 即命中底层 HTTP 超时）计为失败；连续失败达 {@code failureThreshold} 后打开熔断，{@code cooldownMillis}
 * 冷却窗内直接短路返回空列表、不再打远程——避免 sidecar 挂起/不可达时每次 inspect 都吃满超时拖累延迟。
 *
 * <p>说明：底层 {@link GuardProviderClient} 契约是「失败即返回空、绝不抛」，无法从返回值区分「无命中」与
 * 「失败」，故以<b>耗时</b>作为失败信号——健康调用 &lt; 超时返回，超时挂起 ≈ 超时阈值。连接被拒等<b>快速</b>
 * 失败本身代价低，不触发熔断（保留下次重试），熔断只针对昂贵的超时挂起。冷却窗结束后下一次调用放行试探，
 * 仍慢则重新计数。线程安全（{@code Atomic*} 计数，无锁）。</p>
 */
public final class CircuitBreakingProviderClient implements GuardProviderClient {

    private final GuardProviderClient delegate;
    private final int failureThreshold;
    private final long slowCallMillis;
    private final long cooldownMillis;
    private final LongSupplier clockMillis;
    private final AtomicInteger consecutiveFailures = new AtomicInteger(0);
    private final AtomicLong openUntilMillis = new AtomicLong(Long.MIN_VALUE);

    public CircuitBreakingProviderClient(GuardProviderClient delegate, int failureThreshold,
            long slowCallMillis, long cooldownMillis) {
        this(delegate, failureThreshold, slowCallMillis, cooldownMillis, System::currentTimeMillis);
    }

    /** 包级构造：注入可控时钟，供单测确定性推进时间（不依赖真实时钟）。 */
    CircuitBreakingProviderClient(GuardProviderClient delegate, int failureThreshold,
            long slowCallMillis, long cooldownMillis, LongSupplier clockMillis) {
        this.delegate = delegate;
        this.failureThreshold = Math.max(1, failureThreshold);
        this.slowCallMillis = slowCallMillis;
        this.cooldownMillis = cooldownMillis;
        this.clockMillis = clockMillis;
    }

    @Override
    public List<ProviderEntity> analyze(String text) {
        if (clockMillis.getAsLong() < openUntilMillis.get()) {
            return List.of();
        }
        long startMillis = clockMillis.getAsLong();
        List<ProviderEntity> result = delegate.analyze(text);
        long elapsedMillis = clockMillis.getAsLong() - startMillis;
        if (elapsedMillis >= slowCallMillis) {
            if (consecutiveFailures.incrementAndGet() >= failureThreshold) {
                openUntilMillis.set(clockMillis.getAsLong() + cooldownMillis);
                consecutiveFailures.set(0);
            }
        } else {
            consecutiveFailures.set(0);
        }
        return result;
    }
}
