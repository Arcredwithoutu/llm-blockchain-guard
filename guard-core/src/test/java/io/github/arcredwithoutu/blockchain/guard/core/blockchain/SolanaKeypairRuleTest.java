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
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import static org.assertj.core.api.Assertions.assertThat;

class SolanaKeypairRuleTest {

    private final SolanaKeypairRule rule = new SolanaKeypairRule();
    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");

    /** 64 个全 0 元素的占位字节数组（无真实密钥材料）。 */
    private static String zeroKeypairArray() {
        return "[" + IntStream.range(0, 64).mapToObj(i -> "0").collect(Collectors.joining(",")) + "]";
    }

    @Test
    void keypairArrayWithContextIsCritical() {
        String text = "solana keypair id.json: " + zeroKeypairArray();
        List<RuleMatch> m = rule.detect(text, ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_SOLANA_KEYPAIR
                && r.riskLevel() == GuardRiskLevel.CRITICAL);
    }

    @Test
    void bareKeypairArrayWithoutContextIsMedium() {
        List<RuleMatch> m = rule.detect(zeroKeypairArray(), ctx);
        assertThat(m).anyMatch(r -> r.entityType() == GuardEntityType.BLOCKCHAIN_SOLANA_KEYPAIR
                && r.riskLevel() == GuardRiskLevel.MEDIUM);
    }

    @Test
    void wrongLengthArrayDoesNotMatch() {
        String shortArray = "[" + IntStream.range(0, 32).mapToObj(i -> "0").collect(Collectors.joining(",")) + "]";
        List<RuleMatch> m = rule.detect("solana keypair " + shortArray, ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void outOfRangeElementDoesNotMatch() {
        // 一个元素为 999（>255），整组不应判 keypair。
        String bad = "[999" + ",0".repeat(63) + "]";
        List<RuleMatch> m = rule.detect("solana keypair " + bad, ctx);
        assertThat(m).isEmpty();
    }

    @Test
    void plainTextDoesNotMatch() {
        List<RuleMatch> m = rule.detect("the solana keypair is stored in id.json", ctx);
        assertThat(m).isEmpty();
    }
}
