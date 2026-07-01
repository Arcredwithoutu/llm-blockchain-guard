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

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.BlockchainSecretScanner;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 会话级跨轮滑窗检测（设计 §8.9）：在 §8.1 单条 {@code inspect} 之外维护会话级滑动窗口，
 * 捕捉用户把助记词/私钥<b>分片跨 2–3 轮粘贴</b>、单条看不出的密钥材料。
 *
 * <p>每轮流程：规范化本轮原文（去标点/空白归一，<b>仅用于检测、不落库原文</b>）→ 追加进
 * {@link ConversationWindowStore} → 取近 N 轮窗口拼接 → 跑 {@link BlockchainSecretScanner}
 * （重点 BIP39 滑窗、64hex 跨行拼接、Base58/Bech32 被换行截断的重组）→ 命中 CRITICAL 返回需阻断信号 + 命中类型。</p>
 *
 * <p>与 §8.6 流式 rolling buffer 区分：那是单次回答内跨 chunk；本类是跨对话轮次跨消息。</p>
 */
public final class ConversationWindowGuard {

    /** 规范化：把非「字母/数字/CJK」字符统一压成单空格，消解标点/换行/全角分隔对跨轮拼接的干扰。 */
    private static final Pattern NON_WORD = Pattern.compile("[^\\p{L}\\p{N}]+");
    /** 去空白变体：移除窗口全部空白，重组被换行/空格截断的连续型密钥。 */
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    private final BlockchainSecretScanner scanner;
    private final ConversationWindowStore store;
    private final int turns;
    private final long ttlSeconds;

    /**
     * @param scanner    链上密钥扫描器（窗口拼接文本上复跑）
     * @param store      滑窗缓冲（默认内存 TTL，bootstrap 可换 Redis）
     * @param turns      回看轮数，{@code <=0} 时取默认 3
     * @param ttlSeconds 缓冲存活秒数，{@code <=0} 时取默认 1800
     */
    public ConversationWindowGuard(BlockchainSecretScanner scanner, ConversationWindowStore store,
            int turns, long ttlSeconds) {
        this.scanner = Objects.requireNonNull(scanner, "scanner");
        this.store = Objects.requireNonNull(store, "store");
        this.turns = turns <= 0 ? 3 : turns;
        this.ttlSeconds = ttlSeconds <= 0 ? 1800L : ttlSeconds;
    }

    /**
     * 检测本轮 + 窗口累积。规范化文本追加进缓冲后，对近 N 轮窗口跑<b>两个变体</b>并 union CRITICAL：
     *
     * <ol>
     * <li><b>空格拼接窗口</b>：保留词序，覆盖 BIP39 助记词（词天然空格分隔）跨轮拼接；</li>
     * <li><b>去空白拼接窗口</b>：移除窗口全部空白，重组被换行/空格截断的<b>连续型密钥</b>
     * （64hex 私钥、WIF、Sui suiprivkey、扩展 key、Stellar seed 等）跨轮粘贴（设计 §8.9）。</li>
     * </ol>
     *
     * <p>去空白变体不会让 BIP39 误命中（词被黏成一串非 wordlist 词，查表失败）；连续型密钥多带 checksum，
     * 巧合拼出合法 checksum 概率极低，且本就是 fail-closed 的跨轮阻断方向，FP 风险可忽略。</p>
     *
     * @param conversationId 会话标识；为空时不缓存也不检测，返回非阻断空结果
     * @param rawText        本轮用户原文（仅在内存内规范化用于检测，不落库）
     * @param ctx            扫描上下文（方向/开关）
     */
    public Result inspectTurn(String conversationId, String rawText, GuardContext ctx) {
        String normalized = normalize(rawText);
        if (conversationId == null || conversationId.isEmpty() || normalized.isEmpty()) {
            return Result.clean();
        }
        store.append(conversationId, normalized, ttlSeconds);
        String window = store.window(conversationId, turns);
        if (window.isEmpty()) {
            return Result.clean();
        }
        Set<GuardEntityType> critical = new LinkedHashSet<>();
        // 变体 1：空格拼接窗口（BIP39 词序）。
        collectCritical(scanner.scan(window, ctx), critical);
        // 变体 2：去空白拼接窗口（重组被换行/空格截断的连续型密钥）。
        String stripped = WHITESPACE.matcher(window).replaceAll("");
        if (!stripped.equals(window) && !stripped.isEmpty()) {
            collectCritical(scanner.scan(stripped, ctx), critical);
        }
        if (critical.isEmpty()) {
            return Result.clean();
        }
        return new Result(true, List.copyOf(critical));
    }

    /** 把 CRITICAL findings 的 entityType 收进集合（跨变体按 entityType 去重 union）。 */
    private static void collectCritical(List<GuardFinding> findings, Set<GuardEntityType> critical) {
        for (GuardFinding finding : findings) {
            if (finding.riskLevel() == GuardRiskLevel.CRITICAL) {
                critical.add(finding.entityType());
            }
        }
    }

    /** 规范化：把所有非字母/数字/CJK 字符压成单空格并 trim，仅用于跨轮拼接检测。 */
    private static String normalize(String rawText) {
        if (rawText == null || rawText.isEmpty()) {
            return "";
        }
        return NON_WORD.matcher(rawText).replaceAll(" ").trim();
    }

    /**
     * 跨轮检测结果：是否需阻断本轮，以及命中的 CRITICAL 实体类型（按首次命中顺序）。
     *
     * @param blocked         窗口拼接后是否命中 CRITICAL 密钥材料（需阻断本轮）
     * @param criticalEntities 命中的 CRITICAL 实体类型，clean 时为空列表
     */
    public record Result(boolean blocked, List<GuardEntityType> criticalEntities) {

        public Result {
            criticalEntities = criticalEntities == null ? List.of() : List.copyOf(criticalEntities);
        }

        private static Result clean() {
            return new Result(false, new ArrayList<>());
        }
    }
}
