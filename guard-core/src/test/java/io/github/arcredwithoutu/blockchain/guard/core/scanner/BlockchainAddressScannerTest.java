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

package io.github.arcredwithoutu.blockchain.guard.core.scanner;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import java.util.List;
import org.junit.jupiter.api.Test;

class BlockchainAddressScannerTest {

    private static final String EVM_ADDRESS = "0x000000000000000000000000000000000000dEaD";
    private static final String EVM_TX_HASH =
            "0x0000000000000000000000000000000000000000000000000000000000000abc";
    private static final String BTC_ADDRESS = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";

    private final BlockchainAddressScanner scanner = new BlockchainAddressScanner();
    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");

    @Test
    void evmAddressClassifiedAsBlockchainAddress() {
        List<GuardFinding> findings = scanner.scan("请分析地址 " + EVM_ADDRESS + " 的余额", ctx);
        assertThat(findings).extracting(GuardFinding::entityType)
                .containsExactly(GuardEntityType.BLOCKCHAIN_ADDRESS);
    }

    @Test
    void base58BitcoinAddressClassifiedAsBlockchainAddress() {
        List<GuardFinding> findings = scanner.scan("向 " + BTC_ADDRESS + " 转账 0.01 BTC", ctx);
        assertThat(findings).extracting(GuardFinding::entityType)
                .containsExactly(GuardEntityType.BLOCKCHAIN_ADDRESS);
    }

    @Test
    void zeroXPrefixed64HexClassifiedAsTxHash() {
        List<GuardFinding> findings = scanner.scan("tx_hash: " + EVM_TX_HASH, ctx);
        assertThat(findings).extracting(GuardFinding::entityType)
                .containsExactly(GuardEntityType.BLOCKCHAIN_TX_HASH);
    }

    @Test
    void bare64HexWithoutPrefixNotClassified() {
        List<GuardFinding> findings = scanner.scan(
                "sha256: 0000000000000000000000000000000000000000000000000000000000000001", ctx);
        assertThat(findings).isEmpty();
    }

    @Test
    void ensNameNotClassified() {
        List<GuardFinding> findings = scanner.scan("请查询 vitalik.eth 的链上活动", ctx);
        assertThat(findings).isEmpty();
    }

    @Test
    void plainTextNotClassified() {
        List<GuardFinding> findings = scanner.scan("今天天气真不错，我们去公园散步吧。", ctx);
        assertThat(findings).isEmpty();
    }

    @Test
    void addressInsideJsonValueDetected() {
        List<GuardFinding> findings = scanner.scan("{\"to_address\": \"" + EVM_ADDRESS + "\"}", ctx);
        assertThat(findings).extracting(GuardFinding::entityType)
                .containsExactly(GuardEntityType.BLOCKCHAIN_ADDRESS);
    }

    @Test
    void addressSpanIsExact() {
        String input = "addr " + EVM_ADDRESS + " end";
        List<GuardFinding> findings = scanner.scan(input, ctx);
        assertThat(findings).hasSize(1);
        GuardFinding hit = findings.get(0);
        assertThat(input.substring(hit.start(), hit.end())).isEqualTo(EVM_ADDRESS);
    }

    @Test
    void addressRiskLevelIsLow() {
        List<GuardFinding> findings = scanner.scan(EVM_ADDRESS, ctx);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).riskLevel()).isEqualTo(GuardRiskLevel.LOW);
    }
}
