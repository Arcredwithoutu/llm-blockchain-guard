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

/**
 * 审计落地 SPI（设计 §4.2 步 6）：接收 {@link GuardEvent} 并持久化/上报。
 *
 * <p>实现约定：审计绝不能影响主链路——{@code record} 应吞掉自身异常，不向调用方抛出；
 * 且事件中只含 HMAC 指纹，不含原文。默认实现 {@link LoggingGuardAuditSink}；
 * bootstrap 可提供 MySQL 实现覆盖。</p>
 */
public interface GuardAuditSink {

    /** 记录一条审计事件（每个命中一条）。实现须保证不抛异常、不写原文。 */
    void record(GuardEvent event);
}
