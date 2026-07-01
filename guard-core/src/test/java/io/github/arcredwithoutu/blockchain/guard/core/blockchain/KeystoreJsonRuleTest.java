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

class KeystoreJsonRuleTest {

    private final KeystoreJsonRule rule = new KeystoreJsonRule();
    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");
    // 占位 keystore：结构齐全但 ciphertext/mac/address 均为零占位，无真实密钥。
    private static final String KEYSTORE = "{"
            + "\"address\":\"0000000000000000000000000000000000000000\","
            + "\"crypto\":{"
            + "\"cipher\":\"aes-128-ctr\","
            + "\"ciphertext\":\"0000000000000000000000000000000000000000000000000000000000000000\","
            + "\"kdf\":\"scrypt\","
            + "\"mac\":\"0000000000000000000000000000000000000000000000000000000000000000\"},"
            + "\"version\":3}";

    @Test
    void web3KeystoreIsCritical() {
        List<RuleMatch> m = rule.detect(KEYSTORE, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_KEYSTORE_JSON
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void missingAddressDoesNotMatch() {
        String noAddress = KEYSTORE.replace("\"address\":\"0000000000000000000000000000000000000000\",", "");
        List<RuleMatch> m = rule.detect(noAddress, ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void plainJsonWithoutCryptoDoesNotMatch() {
        List<RuleMatch> m = rule.detect("{\"address\":\"0xabc\",\"balance\":100}", ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void plainTextDoesNotMatch() {
        List<RuleMatch> m = rule.detect("the keystore crypto address discussion", ctx);
        assertThat(m).isEmpty();
    }
}
