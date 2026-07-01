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

package io.github.arcredwithoutu.blockchain.guard.core.codec;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.assertj.core.api.Assertions.assertThat;

class Secp256k1RangeTest {
    @Test
    void oneIsValid() {
        assertThat(Secp256k1Range.isValidPrivateKey(BigInteger.ONE)).isTrue();
    }
    @Test
    void zeroIsInvalid() {
        assertThat(Secp256k1Range.isValidPrivateKey(BigInteger.ZERO)).isFalse();
    }
    @Test
    void orderAndAboveInvalid() {
        BigInteger n = Secp256k1Range.order();
        assertThat(Secp256k1Range.isValidPrivateKey(n)).isFalse();
        assertThat(Secp256k1Range.isValidPrivateKey(n.subtract(BigInteger.ONE))).isTrue(); // n-1 合法
    }
    @Test
    void orderMatchesPublishedConstant() {
        // SEC2 secp256k1 阶（公开常量）
        BigInteger expected = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        assertThat(Secp256k1Range.order()).isEqualTo(expected);
    }
}
