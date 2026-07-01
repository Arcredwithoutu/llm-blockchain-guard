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

import io.github.arcredwithoutu.blockchain.guard.core.codec.Bech32;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class SuiPrivateKeyRuleTest {

    private final SuiPrivateKeyRule rule = new SuiPrivateKeyRule();
    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");

    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] GENERATOR = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

    /**
     * 测试内 Bech32 编码（仅测试用，core codec 无 encode）：构造合法 suiprivkey 占位串。
     * payload = flag(1) + 32 字节占位 key（全 0），无真实密钥。
     */
    private static String encodeSuiPrivkey(int flag) {
        byte[] raw = new byte[33];
        raw[0] = (byte) flag;
        // 其余 32 字节保持全 0（占位 key）
        byte[] data = Bech32.convertBits(raw, 8, 5, true);
        return encode("suiprivkey", data);
    }

    private static String encode(String hrp, byte[] data) {
        byte[] checksum = createChecksum(hrp, data);
        StringBuilder sb = new StringBuilder(hrp).append('1');
        for (byte b : data) {
            sb.append(CHARSET.charAt(b));
        }
        for (byte b : checksum) {
            sb.append(CHARSET.charAt(b));
        }
        return sb.toString();
    }

    private static byte[] createChecksum(String hrp, byte[] data) {
        int[] expanded = hrpExpand(hrp);
        int[] values = new int[expanded.length + data.length + 6];
        System.arraycopy(expanded, 0, values, 0, expanded.length);
        for (int i = 0; i < data.length; i++) {
            values[expanded.length + i] = data[i];
        }
        int polymod = polymod(values) ^ 1; // BECH32_CONST = 1
        byte[] checksum = new byte[6];
        for (int i = 0; i < 6; i++) {
            checksum[i] = (byte) ((polymod >>> (5 * (5 - i))) & 31);
        }
        return checksum;
    }

    private static int[] hrpExpand(String hrp) {
        int[] out = new int[hrp.length() * 2 + 1];
        for (int i = 0; i < hrp.length(); i++) {
            out[i] = hrp.charAt(i) >>> 5;
            out[hrp.length() + 1 + i] = hrp.charAt(i) & 31;
        }
        return out;
    }

    private static int polymod(int[] values) {
        int chk = 1;
        for (int v : values) {
            int top = chk >>> 25;
            chk = (chk & 0x1ffffff) << 5 ^ v;
            for (int i = 0; i < 5; i++) {
                chk ^= ((top >>> i) & 1) != 0 ? GENERATOR[i] : 0;
            }
        }
        return chk;
    }

    @Test
    void suiPrivkeyWithFlag0IsCritical() {
        String key = encodeSuiPrivkey(0x00);
        List<RuleMatch> m = rule.detect("sui key: " + key, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_SUI_PRIVKEY
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void suiPrivkeyWithFlag1IsCritical() {
        String key = encodeSuiPrivkey(0x01);
        List<RuleMatch> m = rule.detect(key, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_SUI_PRIVKEY);
    }

    @Test
    void plainBech32WithWrongHrpDoesNotMatch() {
        // 用 bc(bitcoin) HRP 的占位串不应命中 sui 规则（token 正则要求 suiprivkey 前缀）。
        List<RuleMatch> m = rule.detect("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void plainTextDoesNotMatch() {
        List<RuleMatch> m = rule.detect("the suiprivkey format is bech32 encoded", ctx);
        assertThat(m).isEmpty();
    }
}
