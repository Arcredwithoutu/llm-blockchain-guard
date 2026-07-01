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

package io.github.arcredwithoutu.blockchain.guard.core.api;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardDecision;

/**
 * 内核总入口（设计 §4.2）：对一段文本在给定上下文下做检测 → 决策 → 脱敏/阻断 → 审计，返回 {@link GuardDecision}。
 *
 * <p>不依赖 Spring；由 starter 装配为 bean，亦可纯 POJO 手工构造（保证 core 可脱离 Spring 使用）。</p>
 */
public interface GuardrailService {

    /** 检测并处置文本：BLOCK 时 {@code sanitizedText} 为安全提示（不回显原文），MASK 时为脱敏文本，ALLOW 时为原文。 */
    GuardDecision inspect(String text, GuardContext ctx);
}
