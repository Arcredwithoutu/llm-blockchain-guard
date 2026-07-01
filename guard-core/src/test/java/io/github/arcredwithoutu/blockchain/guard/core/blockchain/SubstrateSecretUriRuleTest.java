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

class SubstrateSecretUriRuleTest {

    private final SubstrateSecretUriRule rule = new SubstrateSecretUriRule();
    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");
    // 占位 raw seed（全 0），非真实密钥。
    private static final String ZERO_SEED = "0x" + "0".repeat(64);
    // 占位助记词式词串（12 个常见 wordlist 词，配 SURI 派生路径仅作形态测试）。
    private static final String PLACEHOLDER_WORDS =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    @Test
    void suriWithHardDerivationIsCritical() {
        String suri = PLACEHOLDER_WORDS + "//hard/soft";
        List<RuleMatch> m = rule.detect("seed: " + suri, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_SUBSTRATE_SECRET_URI
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void suriWithPasswordIsCritical() {
        String suri = ZERO_SEED + "///mypassword";
        List<RuleMatch> m = rule.detect(suri, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_SUBSTRATE_SECRET_URI);
    }

    @Test
    void rawSeedWithSubstrateContextIsCritical() {
        List<RuleMatch> m = rule.detect("sr25519 keypair seed " + ZERO_SEED, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_SUBSTRATE_SECRET_URI
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void rawSeedWithoutSubstrateContextDoesNotMatch() {
        // 无 substrate 上下文的裸 0x64hex 不由本规则处理（交 EVM 规则）。
        List<RuleMatch> m = rule.detect("value " + ZERO_SEED, ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void plainTextDoesNotMatch() {
        List<RuleMatch> m = rule.detect("substrate suri derivation is documented in polkadot.js", ctx);
        assertThat(m).isEmpty();
    }
}
