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

import org.bouncycastle.crypto.digests.SHA256Digest;
import java.math.BigInteger;
import java.util.Optional;

public final class Base58Check {

    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);

    private Base58Check() {
    }

    /** 解码并校验 4 字节 double-SHA256 checksum；失败（非法字符/长度不足/校验不符）返回 empty，绝不抛异常。 */
    public static Optional<byte[]> decode(String input) {
        if (input == null || input.isEmpty()) {
            return Optional.empty();
        }
        BigInteger num = BigInteger.ZERO;
        for (int i = 0; i < input.length(); i++) {
            int digit = ALPHABET.indexOf(input.charAt(i));
            if (digit < 0) {
                return Optional.empty();
            }
            num = num.multiply(BASE).add(BigInteger.valueOf(digit));
        }
        byte[] bytes = num.toByteArray();
        // 去掉 BigInteger 符号位可能引入的前导 0x00
        int offset = (bytes.length > 1 && bytes[0] == 0) ? 1 : 0;
        int leadingZeros = 0;
        for (int i = 0; i < input.length() && input.charAt(i) == '1'; i++) {
            leadingZeros++;
        }
        byte[] full = new byte[leadingZeros + (bytes.length - offset)];
        System.arraycopy(bytes, offset, full, leadingZeros, bytes.length - offset);
        if (full.length < 4) {
            return Optional.empty();
        }
        byte[] payload = new byte[full.length - 4];
        System.arraycopy(full, 0, payload, 0, payload.length);
        byte[] checksum = doubleSha256(payload);
        for (int i = 0; i < 4; i++) {
            if (checksum[i] != full[payload.length + i]) {
                return Optional.empty();
            }
        }
        return Optional.of(payload);
    }

    public static String encode(byte[] payload) {
        byte[] checksum = doubleSha256(payload);
        byte[] full = new byte[payload.length + 4];
        System.arraycopy(payload, 0, full, 0, payload.length);
        System.arraycopy(checksum, 0, full, payload.length, 4);
        StringBuilder sb = new StringBuilder();
        BigInteger num = new BigInteger(1, full);
        while (num.signum() > 0) {
            BigInteger[] divmod = num.divideAndRemainder(BASE);
            sb.append(ALPHABET.charAt(divmod[1].intValue()));
            num = divmod[0];
        }
        for (int i = 0; i < full.length && full[i] == 0; i++) {
            sb.append('1');
        }
        return sb.reverse().toString();
    }

    static byte[] doubleSha256(byte[] data) {
        return sha256(sha256(data));
    }

    static byte[] sha256(byte[] data) {
        SHA256Digest digest = new SHA256Digest();
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }
}
