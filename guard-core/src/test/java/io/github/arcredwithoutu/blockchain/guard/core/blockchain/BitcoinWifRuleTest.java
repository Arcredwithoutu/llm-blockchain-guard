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

package io.github.arcredwithoutu.blockchain.guard.core.blockchain;

import io.github.arcredwithoutu.blockchain.guard.core.codec.Base58Check;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class BitcoinWifRuleTest {

    private final BitcoinWifRule rule = new BitcoinWifRule();
    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");

    /** 运行时构造合法 checksum 的占位 WIF：version + 32 字节占位 key（全 0，无资金）。 */
    private static String placeholderWif(int version, boolean compressed) {
        byte[] payload = new byte[compressed ? 34 : 33];
        payload[0] = (byte) version;
        // key 字节保持全 0（占位，非真实私钥）
        if (compressed) {
            payload[payload.length - 1] = 0x01;
        }
        return Base58Check.encode(payload);
    }

    @Test
    void mainnetUncompressedWifIsCritical() {
        String wif = placeholderWif(0x80, false);
        List<RuleMatch> m = rule.detect("key: " + wif, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_WIF
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void mainnetCompressedWifIsCritical() {
        String wif = placeholderWif(0x80, true);
        List<RuleMatch> m = rule.detect(wif, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_WIF);
    }

    @Test
    void testnetWifIsCritical() {
        String wif = placeholderWif(0xEF, true);
        List<RuleMatch> m = rule.detect(wif, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_WIF);
    }

    @Test
    void wrongVersionDoesNotMatch() {
        // version 0x00 (P2PKH address prefix), 同长度但非 WIF version。
        String notWif = placeholderWif(0x00, true);
        List<RuleMatch> m = rule.detect(notWif, ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void invalidChecksumStringDoesNotMatch() {
        // 51 字符占位串：含 base58 字母但末尾 checksum 必然不符，确定性非真实密钥。
        String bogus = "5".repeat(51);
        List<RuleMatch> m = rule.detect(bogus, ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void plainBase58AddressDoesNotMatch() {
        // 34 字符的普通 base58 串（非 51/52 长度），不进入 WIF 判定。
        List<RuleMatch> m = rule.detect("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", ctx);
        assertThat(m).noneMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_WIF);
    }

    // I1：WIF 紧贴非 base58 分隔符（=、引号），边界环视应精确锁定 51/52 串仍命中。
    @Test
    void wifAdjacentToNonBase58SeparatorIsStillDetected() {
        String wif = placeholderWif(0x80, false);
        List<RuleMatch> equals = rule.detect("key=" + wif + ";", ctx);
        assertThat(equals).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_WIF);
        List<RuleMatch> quoted = rule.detect("\"" + wif + "\"", ctx);
        assertThat(quoted).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_WIF);
    }

    // I1：更长 base58 run（WIF 后粘连额外 base58 字符）不应以偏移窗口误命中（边界要求恰 51/52）。
    @Test
    void wifGluedToExtraBase58CharsDoesNotMisalign() {
        String wif = placeholderWif(0x80, false);
        // 在 51 字符 WIF 后直接粘 4 个 base58 字符 → 整体成 55 字符 run，边界要求恰 51/52，不命中偏移窗口。
        List<RuleMatch> m = rule.detect(wif + "ABCD", ctx);
        assertThat(m).noneMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_WIF);
    }
}
