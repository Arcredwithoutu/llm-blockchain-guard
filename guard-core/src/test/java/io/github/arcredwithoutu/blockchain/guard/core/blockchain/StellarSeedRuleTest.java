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

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class StellarSeedRuleTest {

    private final StellarSeedRule rule = new StellarSeedRule();
    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");

    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /**
     * 测试内构造合法 StrKey secret seed 占位串：version 0x90 + 32 字节占位（全 0）+ CRC16。
     * 32 字节 payload 为全 0（无真实密钥），仅校验结构判定逻辑。
     */
    private static String encodeSecretSeed() {
        byte[] payload = new byte[33];
        payload[0] = (byte) 0x90;
        // 其余 32 字节保持全 0（占位 seed）
        int crc = crc16XModem(payload, payload.length);
        byte[] full = new byte[35];
        System.arraycopy(payload, 0, full, 0, 33);
        full[33] = (byte) (crc & 0xff);
        full[34] = (byte) ((crc >>> 8) & 0xff);
        return base32Encode(full);
    }

    private static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int acc = 0;
        int bits = 0;
        for (byte b : data) {
            acc = (acc << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                sb.append(BASE32.charAt((acc >>> bits) & 31));
            }
        }
        if (bits > 0) {
            sb.append(BASE32.charAt((acc << (5 - bits)) & 31));
        }
        return sb.toString();
    }

    private static int crc16XModem(byte[] data, int len) {
        int crc = 0x0000;
        for (int i = 0; i < len; i++) {
            crc ^= (data[i] & 0xff) << 8;
            for (int b = 0; b < 8; b++) {
                crc = ((crc & 0x8000) != 0) ? ((crc << 1) ^ 0x1021) : (crc << 1);
                crc &= 0xffff;
            }
        }
        return crc;
    }

    @Test
    void stellarSecretSeedIsCritical() {
        String seed = encodeSecretSeed();
        List<RuleMatch> m = rule.detect("stellar secret seed: " + seed, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_STELLAR_SECRET_SEED
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void stellarSecretSeedWithoutContextStillMatchesByStructure() {
        // 结构（version+CRC）即强信号，无需上下文。
        String seed = encodeSecretSeed();
        List<RuleMatch> m = rule.detect(seed, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_STELLAR_SECRET_SEED);
    }

    @Test
    void publicKeyPrefixDoesNotMatch() {
        // 'G' 前缀（public key）不满足 'S' secret seed token 正则。
        List<RuleMatch> m = rule.detect("GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUV", ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void badChecksumStringDoesNotMatch() {
        // 56 字符的 S 前缀占位串，CRC16 几乎不可能合法。
        List<RuleMatch> m = rule.detect("S" + "A".repeat(55), ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void plainTextDoesNotMatch() {
        List<RuleMatch> m = rule.detect("the stellar secret seed begins with S", ctx);
        assertThat(m).isEmpty();
    }
}
