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

import io.github.arcredwithoutu.blockchain.guard.core.blockchain.Bip39MnemonicRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.BlockchainSecretDetector;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.EvmPrivateKeyHexRule;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.BlockchainSecretScanner;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class ConversationWindowGuardTest {

    private final GuardContext ctx = GuardContext.userInput("t", "tr", "conv-1", "u");
    private final BlockchainSecretScanner scanner = new BlockchainSecretScanner(
            new BlockchainSecretDetector(List.of(
                    new EvmPrivateKeyHexRule(true),
                    new Bip39MnemonicRule(List.of("english"), true))));

    // BIP39 全零熵标准测试向量（公开、无资金），12 词。跨轮按词边界分片。
    private static final String[] ZERO_ENTROPY_PARTS = {
        "abandon abandon abandon abandon",
        "abandon abandon abandon abandon",
        "abandon abandon abandon about",
    };

    // 范围内占位私钥 64hex（63 个 0 + 末位 1，合法范围但非真实钱包）。
    // 分 3 片跨轮，分片边界故意落在 hex 中间：片1 "私钥 0x"+16hex、片2 16hex、片3 32hex(31×0+末位1)，共 64hex。
    private static final String[] HEX_KEY_PARTS = {
        "私钥 0x0000000000000000",
        "0000000000000000",
        "00000000000000000000000000000001",
    };

    @Test
    void mnemonicSplitAcrossThreeTurnsHitsCritical() {
        ConversationWindowGuard guard = new ConversationWindowGuard(scanner, store(), 3, 1800);
        // 前两轮各 4 词，单轮不足以命中。
        assertThat(guard.inspectTurn("conv-1", ZERO_ENTROPY_PARTS[0], ctx).blocked()).isFalse();
        assertThat(guard.inspectTurn("conv-1", ZERO_ENTROPY_PARTS[1], ctx).blocked()).isFalse();
        // 第三轮补齐 12 词，窗口拼接后命中 CRITICAL。
        ConversationWindowGuard.Result result = guard.inspectTurn("conv-1", ZERO_ENTROPY_PARTS[2], ctx);
        assertThat(result.blocked()).isTrue();
        assertThat(result.criticalEntities()).contains(GuardEntityType.BLOCKCHAIN_MNEMONIC);
    }

    @Test
    void mnemonicSplitAcrossTwoTurnsHitsCritical() {
        ConversationWindowGuard guard = new ConversationWindowGuard(scanner, store(), 3, 1800);
        assertThat(guard.inspectTurn("conv-1", "abandon abandon abandon abandon abandon abandon", ctx)
                .blocked()).isFalse();
        ConversationWindowGuard.Result result =
                guard.inspectTurn("conv-1", "abandon abandon abandon abandon abandon about", ctx);
        assertThat(result.blocked()).isTrue();
        assertThat(result.criticalEntities()).contains(GuardEntityType.BLOCKCHAIN_MNEMONIC);
    }

    @Test
    void hexKeySplitAcrossTurnsHitsViaWhitespaceStrippedVariant() {
        // 连续型 64hex 私钥被换行/空格截断跨 3 轮粘贴：空格拼接窗口里 hex 段不连续（[0-9a-f]{64} 匹配不到），
        // 去空白变体把碎片重组成连续 64hex → 命中 CRITICAL（证明新增的去空白变体起作用）。
        ConversationWindowGuard guard = new ConversationWindowGuard(scanner, store(), 3, 1800);
        assertThat(guard.inspectTurn("conv-1", HEX_KEY_PARTS[0], ctx).blocked()).isFalse();
        assertThat(guard.inspectTurn("conv-1", HEX_KEY_PARTS[1], ctx).blocked()).isFalse();
        ConversationWindowGuard.Result result = guard.inspectTurn("conv-1", HEX_KEY_PARTS[2], ctx);
        assertThat(result.blocked()).isTrue();
        assertThat(result.criticalEntities()).contains(GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX);
    }

    @Test
    void spaceJoinedWindowAloneMissesSplitHexKey() {
        // 锁死「漏检」前提：仅靠空格拼接窗口（不去空白），被截断的 hex 碎片不连续 → 不命中。
        // 此处用一个 turns 很大、但只跑空格拼接判定的间接证明：把三片以空格拼成一段送单条 scan，应无 CRITICAL。
        String spaceJoined = String.join(" ", HEX_KEY_PARTS);
        assertThat(scanner.scan(spaceJoined, ctx))
                .noneMatch(f -> f.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX
                        && f.riskLevel() == io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel.CRITICAL);
    }

    @Test
    void firstHalfDroppedOutOfWindowDoesNotHit() {
        // turns=2：前两轮各 6 词的前半被挤出窗口，最后两轮无法补齐 12 词 → 不误命中。
        ConversationWindowGuard guard = new ConversationWindowGuard(scanner, store(), 2, 1800);
        guard.inspectTurn("conv-1", "abandon abandon abandon abandon abandon abandon", ctx);
        guard.inspectTurn("conv-1", "abandon abandon abandon abandon abandon abandon", ctx);
        // 第三、四轮把前两轮挤出窗口（窗口只看近 2 轮）。
        assertThat(guard.inspectTurn("conv-1", "请问以太坊", ctx).blocked()).isFalse();
        assertThat(guard.inspectTurn("conv-1", "和比特币区别", ctx).blocked()).isFalse();
    }

    @Test
    void expiredTurnsDoNotHit() {
        // 过期项不参与窗口拼接：直接对 store 注入一条短 TTL 的早轮，等其过期后再补后续片，
        // 窗口剔除过期项 → 无法拼出完整助记词 → 不误命中。
        ConversationWindowStore store = store();
        ConversationWindowGuard guard = new ConversationWindowGuard(scanner, store, 3, 1800);
        // 第一片以 1 秒 TTL 写入，随后等待其过期。
        store.append("conv-1", "abandon abandon abandon abandon abandon abandon", 1);
        sleepUntilExpired();
        assertThat(guard.inspectTurn("conv-1", "abandon abandon abandon abandon abandon about", ctx)
                .blocked()).isFalse();
    }

    private static void sleepUntilExpired() {
        long deadline = System.currentTimeMillis() + 1100L;
        while (System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(50L);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted while waiting for TTL expiry", ex);
            }
        }
    }

    @Test
    void cleanConversationNeverBlocks() {
        ConversationWindowGuard guard = new ConversationWindowGuard(scanner, store(), 3, 1800);
        assertThat(guard.inspectTurn("conv-1", "以太坊是什么", ctx).blocked()).isFalse();
        assertThat(guard.inspectTurn("conv-1", "怎么买比特币", ctx).blocked()).isFalse();
        assertThat(guard.inspectTurn("conv-1", "Gas 费怎么算", ctx).blocked()).isFalse();
    }

    @Test
    void blankConversationIdReturnsCleanWithoutCaching() {
        ConversationWindowGuard guard = new ConversationWindowGuard(scanner, store(), 3, 1800);
        ConversationWindowGuard.Result result = guard.inspectTurn("", ZERO_ENTROPY_PARTS[0], ctx);
        assertThat(result.blocked()).isFalse();
        assertThat(result.criticalEntities()).isEmpty();
    }

    @Test
    void separateConversationsDoNotShareWindow() {
        ConversationWindowGuard guard = new ConversationWindowGuard(scanner, store(), 3, 1800);
        guard.inspectTurn("conv-A", ZERO_ENTROPY_PARTS[0], ctx);
        guard.inspectTurn("conv-A", ZERO_ENTROPY_PARTS[1], ctx);
        // 另一会话补最后一片，不应命中（窗口按 conversationId 隔离）。
        assertThat(guard.inspectTurn("conv-B", ZERO_ENTROPY_PARTS[2], ctx).blocked()).isFalse();
    }

    private static ConversationWindowStore store() {
        return new InMemoryConversationWindowStore();
    }
}
