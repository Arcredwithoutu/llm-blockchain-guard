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

import java.util.Locale;
import java.util.Optional;

public final class Bech32 {

    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] GENERATOR = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    private static final int BECH32_CONST = 1;
    private static final int BECH32M_CONST = 0x2bc830a3;

    public record Decoded(String hrp, byte[] data, boolean bech32m) {}

    private Bech32() {
    }

    public static Optional<Decoded> decode(String input) {
        if (input == null || input.length() < 8 || input.length() > 1000) {
            return Optional.empty();
        }
        boolean hasLower = !input.equals(input.toUpperCase(Locale.ROOT));
        boolean hasUpper = !input.equals(input.toLowerCase(Locale.ROOT));
        if (hasLower && hasUpper) {
            return Optional.empty();
        }
        String s = input.toLowerCase(Locale.ROOT);
        int sep = s.lastIndexOf('1');
        if (sep < 1 || sep + 7 > s.length()) {
            return Optional.empty();
        }
        String hrp = s.substring(0, sep);
        byte[] data = new byte[s.length() - sep - 1];
        for (int i = 0; i < data.length; i++) {
            int v = CHARSET.indexOf(s.charAt(sep + 1 + i));
            if (v < 0) {
                return Optional.empty();
            }
            data[i] = (byte) v;
        }
        if (data.length < 6) {                // checksum 占 6，防 payload 负长度（参考 R1 健壮性加固）
            return Optional.empty();
        }
        int check = polymod(hrpExpand(hrp), data);
        boolean isBech32m = check == BECH32M_CONST;
        if (check != BECH32_CONST && !isBech32m) {
            return Optional.empty();
        }
        byte[] payload = new byte[data.length - 6];
        System.arraycopy(data, 0, payload, 0, payload.length);
        return Optional.of(new Decoded(hrp, payload, isBech32m));
    }

    private static int polymod(int[] hrpExp, byte[] data) {
        int chk = 1;
        for (int v : hrpExp) {
            chk = step(chk, v);
        }
        for (byte v : data) {
            chk = step(chk, v);
        }
        return chk;
    }

    private static int step(int chk, int value) {
        int top = chk >>> 25;
        chk = (chk & 0x1ffffff) << 5 ^ value;
        for (int i = 0; i < 5; i++) {
            chk ^= ((top >>> i) & 1) != 0 ? GENERATOR[i] : 0;
        }
        return chk;
    }

    private static int[] hrpExpand(String hrp) {
        int[] out = new int[hrp.length() * 2 + 1];
        for (int i = 0; i < hrp.length(); i++) {
            out[i] = hrp.charAt(i) >>> 5;
            out[hrp.length() + 1 + i] = hrp.charAt(i) & 31;
        }
        out[hrp.length()] = 0;
        return out;
    }

    /** 5-bit ⇄ 8-bit 重组（pad=true 用于打包，false 用于解包并要求无残留位）。失败返回 null。 */
    public static byte[] convertBits(byte[] data, int from, int to, boolean pad) {
        int acc = 0, bits = 0;
        int maxv = (1 << to) - 1;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (byte b : data) {
            int value = b & 0xff;
            if ((value >>> from) != 0) {
                return null;
            }
            acc = (acc << from) | value;
            bits += from;
            while (bits >= to) {
                bits -= to;
                out.write((acc >>> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0) {
                out.write((acc << (to - bits)) & maxv);
            }
        } else if (bits >= from || ((acc << (to - bits)) & maxv) != 0) {
            return null;
        }
        return out.toByteArray();
    }
}
