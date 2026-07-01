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

/**
 * 远程 guardrail provider 客户端 SPI（设计 §9.3 / R3）：把文本送外部分析服务（Presidio / LLM Guard）
 * 做<b>语义补充</b>，返回实体命中。
 *
 * <p>红线（§9.3）：调用方<b>必先本地 secret scrub</b>，provider 绝不前置接收私钥原文；本接口仅做 PII/注入类
 * 语义增强。所有实现遵守<b>超时/异常即降级返回空列表、绝不抛出</b>——远程不可用时本地确定性判定不受影响。</p>
 */
public interface GuardProviderClient {

    /**
     * 分析文本并返回实体命中。<b>任何网络/超时/解析失败都返回空列表，不抛异常</b>。
     *
     * @param text 已完成本地 secret scrub 的文本
     * @return 实体命中列表；不可用/无命中时为空列表，绝不为 {@code null}
     */
    List<ProviderEntity> analyze(String text);
}
