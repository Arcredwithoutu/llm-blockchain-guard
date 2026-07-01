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

class Base58CheckTest {

    // 比特币创世地址（公开非密材料）：Base58Check decode → version 0x00 + 20 字节 hash160
    private static final String GENESIS_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";

    @Test
    void decodesKnownPublicAddress() {
        Optional<byte[]> decoded = Base58Check.decode(GENESIS_ADDRESS);
        assertThat(decoded).isPresent();
        assertThat(decoded.get().length).isEqualTo(21);      // 1 version + 20 payload
        assertThat(decoded.get()[0] & 0xFF).isEqualTo(0x00); // mainnet P2PKH version
    }

    @Test
    void rejectsCorruptedChecksum() {
        // 改末位字符 → checksum 失败
        String corrupted = GENESIS_ADDRESS.substring(0, GENESIS_ADDRESS.length() - 1) + "X";
        assertThat(Base58Check.decode(corrupted)).isEmpty();
    }

    @Test
    void rejectsNonBase58Char() {
        assertThat(Base58Check.decode("0OIl")).isEmpty(); // 0 O I l 不在字母表
    }

    @Test
    void roundTripsLeadingZeroPayload() {
        // 以 0x00 开头是 encode/decode 前导零路径最脆弱点（参考 R1 Nayuki 核对结论）：
        // payload 首字节 0x00 → 编码串须以 '1' 开头，且 round-trip 完整恢复前导 0x00。
        byte[] payload = new byte[] {0x00, 1, 2, 3, 4, 5};
        String encoded = Base58Check.encode(payload);
        assertThat(encoded).startsWith("1");
        assertThat(Base58Check.decode(encoded)).isPresent();
        assertThat(Base58Check.decode(encoded).get()).containsExactly(payload);
    }
}
