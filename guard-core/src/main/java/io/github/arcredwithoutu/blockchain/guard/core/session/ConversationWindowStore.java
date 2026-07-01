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

package io.github.arcredwithoutu.blockchain.guard.core.session;

/**
 * 会话级滑窗缓冲 SPI（设计 §8.9）：按 {@code conversationId} 维护近 N 轮用户消息的<b>规范化拼接缓冲</b>，
 * 仅供跨轮检测拼接使用，<b>绝不持久化原文</b>。
 *
 * <p>默认实现 {@link InMemoryConversationWindowStore}（内存 + TTL）；bootstrap 批次二可换 Redis 实现，
 * 因此本接口故意不绑定任何存储/Spring 细节。</p>
 */
public interface ConversationWindowStore {

    /**
     * 追加一轮规范化文本到指定会话的滑窗缓冲。
     *
     * @param conversationId 会话标识；为空时不做任何操作
     * @param normalizedText 已规范化的本轮文本（去标点/空白归一），由调用方保证不含可逆原文敏感格式
     * @param ttlSeconds     该会话缓冲的存活秒数；非正值视为不缓存
     */
    void append(String conversationId, String normalizedText, long ttlSeconds);

    /**
     * 取指定会话近 {@code turns} 轮规范化文本的拼接（轮次以单空格分隔，最早在前、最近在后）。
     *
     * @param conversationId 会话标识
     * @param turns          回看的最大轮数；非正值返回空串
     * @return 拼接后的窗口文本；无缓冲/已过期返回空串，绝不返回 {@code null}
     */
    String window(String conversationId, int turns);
}
