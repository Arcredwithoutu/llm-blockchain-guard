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
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Stellar StrKey secret seed 检测规则：{@code S...} 开头、base32（RFC4648）56 字符，
 * 解码后 version byte = {@code 0x90}（ed25519 secret seed）且 CRC16-XModem 校验通过 → CRITICAL。
 */
public final class StellarSeedRule implements DetectionRule {

    private static final String RULE_ID = "stellar-seed";
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    // StrKey secret seed：'S' 前缀 + 55 个 base32 字符，共 56。
    private static final Pattern TOKEN = Pattern.compile("S[A-Z2-7]{55}");
    private static final int VERSION_SECRET_SEED = 0x90;
    // 1(version) + 32(payload) + 2(crc16) = 35 字节。
    private static final int EXPECTED_BYTES = 35;

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<RuleMatch> detect(String text, GuardContext ctx) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        List<RuleMatch> matches = new ArrayList<>();
        Matcher matcher = TOKEN.matcher(text);
        while (matcher.find()) {
            if (isStellarSecretSeed(matcher.group())) {
                matches.add(new RuleMatch(GuardEntityType.BLOCKCHAIN_STELLAR_SECRET_SEED, GuardRiskLevel.CRITICAL,
                        0.98, matcher.start(), matcher.end(), RULE_ID, "Stellar StrKey secret seed"));
            }
        }
        return matches;
    }

    private static boolean isStellarSecretSeed(String token) {
        byte[] decoded = base32Decode(token);
        if (decoded == null || decoded.length != EXPECTED_BYTES) {
            return false;
        }
        if ((decoded[0] & 0xff) != VERSION_SECRET_SEED) {
            return false;
        }
        int payloadLen = decoded.length - 2;
        int expectedCrc = ((decoded[payloadLen] & 0xff)) | ((decoded[payloadLen + 1] & 0xff) << 8);
        return crc16XModem(decoded, payloadLen) == expectedCrc;
    }

    /** RFC4648 base32（无 padding），非法字符返回 null。 */
    private static byte[] base32Decode(String input) {
        int acc = 0;
        int bits = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < input.length(); i++) {
            int value = BASE32.indexOf(input.charAt(i));
            if (value < 0) {
                return null;
            }
            acc = (acc << 5) | value;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out.write((acc >>> bits) & 0xff);
            }
        }
        return out.toByteArray();
    }

    /** CRC16-XModem（poly 0x1021，init 0x0000），覆盖 data 前 len 字节。 */
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
}
