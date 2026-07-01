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

class EvmPrivateKeyHexRuleTest {

    private final EvmPrivateKeyHexRule rule = new EvmPrivateKeyHexRule(true);
    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");
    // 越界值（> n，确定性非法私钥；纯占位、无资金）
    private static final String OUT_OF_RANGE = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    // 范围内占位（全 1，合法范围但非真实钱包）
    private static final String IN_RANGE = "0000000000000000000000000000000000000000000000000000000000000001";

    @Test
    void hexWithPrivateKeyContextIsCritical() {
        List<RuleMatch> m = rule.detect("私钥: " + IN_RANGE, ctx);
        assertThat(m).anyMatch(r -> r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void aip80PrefixIsCriticalRegardlessOfCurve() {
        List<RuleMatch> m = rule.detect("ed25519-priv-0x" + OUT_OF_RANGE, ctx);
        assertThat(m).anyMatch(r -> r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    // §6.11/G3：负向上下文（tx_hash/sha256…）下私钥规则不出 finding，0x+64hex 交地址分类器识别为 TX_HASH。
    @Test
    void txHashContextProducesNoPrivateKeyFinding() {
        List<RuleMatch> m = rule.detect("tx_hash: 0x" + IN_RANGE, ctx);
        assertThat(m).noneMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX);
    }

    @Test
    void outOfRangeNoContextNotCritical() {
        List<RuleMatch> m = rule.detect("value " + OUT_OF_RANGE, ctx);
        assertThat(m).noneMatch(r -> r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    // I2：对抗者在同一窗口同时塞负向(sha256)与正向(私钥)上下文，真私钥不应被降级
    @Test
    void positiveContextWinsOverNegativeInjection() {
        List<RuleMatch> m = rule.detect("sha256 私钥: " + IN_RANGE, ctx);
        assertThat(m).anyMatch(r -> r.riskLevel() == GuardRiskLevel.CRITICAL);
    }
}
