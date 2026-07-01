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
import java.util.Optional;
import static org.assertj.core.api.Assertions.assertThat;

class Bech32Test {

    @Test
    void decodesBip173ValidVectors() {
        // BIP173 官方有效测试串（非密钥）
        assertThat(Bech32.decode("A12UEL5L")).isPresent();
        assertThat(Bech32.decode("a12uel5l")).isPresent();
        Optional<Bech32.Decoded> d = Bech32.decode("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw");
        assertThat(d).isPresent();
        assertThat(d.get().hrp()).isEqualTo("abcdef");
        assertThat(d.get().bech32m()).isFalse();
    }

    @Test
    void decodesBip350Bech32mVector() {
        // BIP350 官方 bech32m 向量，锁死 BECH32M_CONST 判别分支（参考 R1）
        Optional<Bech32.Decoded> d = Bech32.decode("A1LQFN3A");
        assertThat(d).isPresent();
        assertThat(d.get().bech32m()).isTrue();
    }

    @Test
    void rejectsBadChecksum() {
        assertThat(Bech32.decode("A12UEL5X")).isEmpty();
    }

    @Test
    void rejectsMixedCase() {
        assertThat(Bech32.decode("A12uEL5L")).isEmpty();
    }

    @Test
    void convertBitsRoundTrip() {
        byte[] eightBit = {0x00, 0x11, 0x22, 0x33};
        byte[] fiveBit = Bech32.convertBits(eightBit, 8, 5, true);
        byte[] back = Bech32.convertBits(fiveBit, 5, 8, false);
        assertThat(back).containsExactly(eightBit);
    }
}
