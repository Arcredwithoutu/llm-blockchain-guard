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

class ExtendedKeyRuleTest {

    private final ExtendedKeyRule rule = new ExtendedKeyRule();
    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");

    /** 构造合法 checksum 的占位扩展密钥：4 字节 version + 74 字节占位（全 0），共 78 字节 payload。 */
    private static String placeholderExtendedKey(int version) {
        byte[] payload = new byte[78];
        payload[0] = (byte) (version >>> 24);
        payload[1] = (byte) (version >>> 16);
        payload[2] = (byte) (version >>> 8);
        payload[3] = (byte) version;
        // 其余 74 字节保持全 0（depth/fingerprint/chaincode/key 占位，无真实密钥）
        return Base58Check.encode(payload);
    }

    @Test
    void xprvIsCriticalExtendedPrivate() {
        String xprv = placeholderExtendedKey(0x0488ADE4);
        List<RuleMatch> m = rule.detect("seed: " + xprv, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_EXTENDED_PRIVATE_KEY
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void xpubIsHighExtendedPublic() {
        String xpub = placeholderExtendedKey(0x0488B21E);
        List<RuleMatch> m = rule.detect(xpub, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_EXTENDED_PUBLIC_KEY
                && r.riskLevel() == GuardRiskLevel.HIGH);
    }

    @Test
    void zprvSegwitIsCriticalExtendedPrivate() {
        String zprv = placeholderExtendedKey(0x04B2430C);
        List<RuleMatch> m = rule.detect(zprv, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_EXTENDED_PRIVATE_KEY);
    }

    @Test
    void unknownVersionDoesNotMatch() {
        // 4 字节 version 不在 SLIP-0132 表内。
        String unknown = placeholderExtendedKey(0x12345678);
        List<RuleMatch> m = rule.detect(unknown, ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void plainTextDoesNotMatch() {
        List<RuleMatch> m = rule.detect("an extended discussion about public keys", ctx);
        assertThat(m).isEmpty();
    }
}
