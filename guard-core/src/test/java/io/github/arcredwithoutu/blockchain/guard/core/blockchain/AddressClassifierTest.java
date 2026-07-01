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

import static org.assertj.core.api.Assertions.assertThat;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import org.junit.jupiter.api.Test;

class AddressClassifierTest {

    @Test
    void evm40HexIsAddress() {
        assertThat(AddressClassifier.classify("0x000000000000000000000000000000000000dEaD"))
                .isEqualTo(GuardEntityType.BLOCKCHAIN_ADDRESS);
    }

    @Test
    void evm64HexIsTxHash() {
        assertThat(AddressClassifier.classify(
                "0x0000000000000000000000000000000000000000000000000000000000000abc"))
                .isEqualTo(GuardEntityType.BLOCKCHAIN_TX_HASH);
    }

    @Test
    void base58IsAddress() {
        assertThat(AddressClassifier.classify("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))
                .isEqualTo(GuardEntityType.BLOCKCHAIN_ADDRESS);
    }

    @Test
    void bare64HexWithoutPrefixIsNotClassified() {
        assertThat(AddressClassifier.classify(
                "0000000000000000000000000000000000000000000000000000000000000001"))
                .isNull();
    }

    @Test
    void randomTokenIsNotClassified() {
        assertThat(AddressClassifier.classify("hello-world")).isNull();
    }

    @Test
    void nullOrEmptyIsNotClassified() {
        assertThat(AddressClassifier.classify(null)).isNull();
        assertThat(AddressClassifier.classify("")).isNull();
    }
}
