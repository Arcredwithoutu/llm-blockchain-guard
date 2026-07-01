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

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 默认内存滑窗实现（设计 §8.9 第 4 点）：每会话维护一个带过期时间的轮次队列，
 * <b>仅驻内存、带 TTL、绝不持久化原文</b>。
 *
 * <p>每轮项记录 {@code expiresAtMillis}，{@link #window} 读取时惰性剔除已过期项；
 * 队列长度不主动截断，由 {@link #window} 的 {@code turns} 参数控制回看范围（取最近 N 项）。
 * 线程安全靠 {@link ConcurrentHashMap} + 队列上的同步块（同会话内串行）。</p>
 */
public final class InMemoryConversationWindowStore implements ConversationWindowStore {

    /** 单会话最多保留的轮次条目，防止异常会话无限堆积内存（超出从队首淘汰）。 */
    private static final int MAX_BUFFERED_TURNS = 64;

    private final Map<String, Deque<Turn>> buffers = new ConcurrentHashMap<>();

    @Override
    public void append(String conversationId, String normalizedText, long ttlSeconds) {
        if (conversationId == null || conversationId.isEmpty() || normalizedText == null
                || normalizedText.isEmpty() || ttlSeconds <= 0) {
            return;
        }
        long expiresAt = System.currentTimeMillis() + ttlSeconds * 1000L;
        Deque<Turn> buffer = buffers.computeIfAbsent(conversationId, key -> new ArrayDeque<>());
        synchronized (buffer) {
            buffer.addLast(new Turn(normalizedText, expiresAt));
            while (buffer.size() > MAX_BUFFERED_TURNS) {
                buffer.pollFirst();
            }
        }
    }

    @Override
    public String window(String conversationId, int turns) {
        if (conversationId == null || conversationId.isEmpty() || turns <= 0) {
            return "";
        }
        Deque<Turn> buffer = buffers.get(conversationId);
        if (buffer == null) {
            return "";
        }
        long now = System.currentTimeMillis();
        StringBuilder joined = new StringBuilder();
        synchronized (buffer) {
            evictExpired(buffer, now);
            if (buffer.isEmpty()) {
                buffers.remove(conversationId, buffer);
                return "";
            }
            int skip = Math.max(0, buffer.size() - turns);
            int index = 0;
            for (Turn turn : buffer) {
                if (index++ < skip) {
                    continue;
                }
                if (joined.length() > 0) {
                    joined.append(' ');
                }
                joined.append(turn.normalizedText);
            }
        }
        return joined.toString();
    }

    /** 从队首起剔除已过期项（队列按追加顺序，过期项集中在较早位置，但 TTL 可不同故逐项判断）。 */
    private static void evictExpired(Deque<Turn> buffer, long now) {
        Iterator<Turn> iterator = buffer.iterator();
        while (iterator.hasNext()) {
            if (iterator.next().expiresAtMillis <= now) {
                iterator.remove();
            }
        }
    }

    /** 单轮缓冲项：规范化文本 + 绝对过期时间（毫秒）。 */
    private record Turn(String normalizedText, long expiresAtMillis) {
    }
}
