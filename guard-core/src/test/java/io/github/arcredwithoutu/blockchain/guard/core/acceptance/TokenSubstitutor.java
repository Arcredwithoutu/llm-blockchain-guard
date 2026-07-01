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

package io.github.arcredwithoutu.blockchain.guard.core.acceptance;

import io.github.arcredwithoutu.blockchain.guard.core.codec.Base58Check;
import io.github.arcredwithoutu.blockchain.guard.core.codec.Bech32;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 用例占位记号 → 运行时编码密钥串的替换器（spec §5.1 runtime-encoded / §8.6）。
 *
 * <p><b>安全铁律</b>：所有占位密钥均以「全零熵 payload」在加载时实时编码，源码与 JSON 中
 * 永不出现完整编码密钥；本类只把全零占位编码出合法 checksum 的串、仅存在于内存。</p>
 *
 * <p>guard-core 的 {@link Base58Check} 自带 encode，但 {@link Bech32} 与 StrKey 无 encode——
 * 故本类在测试侧自实现 Bech32 encode（参考 SuiPrivateKeyRuleTest）与 StrKey base32+CRC16
 * （参考 StellarSeedRuleTest）。</p>
 */
final class TokenSubstitutor {

    private static final Pattern TOKEN = Pattern.compile("<<[^>]+>>");

    // ===== 全零占位字节 =====
    private static final byte[] ZERO_32 = new byte[32];
    private static final byte[] ZERO_74 = new byte[74];

    // ===== SLIP-0132 扩展密钥 version（取自 ExtendedKeyRule，确保命中）=====
    private static final byte[] XPRV_VER = {0x04, (byte) 0x88, (byte) 0xAD, (byte) 0xE4};
    private static final byte[] XPUB_VER = {0x04, (byte) 0x88, (byte) 0xB2, 0x1E};
    private static final byte[] TPRV_VER = {0x04, 0x35, (byte) 0x83, (byte) 0x94};
    private static final byte[] YPRV_VER = {0x04, (byte) 0x9D, 0x78, 0x78};

    // ===== Stellar StrKey =====
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final byte STELLAR_SEED_VERSION = (byte) 0x90;

    // ===== Sui Bech32 =====
    private static final String BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] BECH32_GENERATOR = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

    /** 固定占位 → 完整编码串。 */
    private final Map<String, String> simpleTokens = new LinkedHashMap<>();

    TokenSubstitutor() {
        simpleTokens.put("<<WIF_MAINNET>>", wifMainnet());
        simpleTokens.put("<<WIF_COMPRESSED>>", wifCompressed());
        simpleTokens.put("<<XPRV>>", Base58Check.encode(concat(XPRV_VER, ZERO_74)));
        simpleTokens.put("<<XPUB>>", Base58Check.encode(concat(XPUB_VER, ZERO_74)));
        simpleTokens.put("<<TPRV>>", Base58Check.encode(concat(TPRV_VER, ZERO_74)));
        simpleTokens.put("<<YPRV>>", Base58Check.encode(concat(YPRV_VER, ZERO_74)));
        simpleTokens.put("<<SUI_PRIVKEY>>", suiPrivkey(0x00));
        simpleTokens.put("<<STELLAR_SEED>>", stellarSeed());
        simpleTokens.put("<<SOLANA_KEYPAIR>>", solanaKeypairArray());
    }

    /** 把文本内所有占位记号替换为运行时编码串（仅内存）。 */
    String substitute(String text) {
        if (text == null || text.indexOf("<<") < 0) {
            return text;
        }
        Matcher matcher = TOKEN.matcher(text);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            matcher.appendReplacement(out, Matcher.quoteReplacement(resolve(matcher.group())));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    /** 解析单个占位记号为编码串；含 RUNTIME:codec:... 参数化跨轮分片记号。 */
    private String resolve(String token) {
        String simple = simpleTokens.get(token);
        if (simple != null) {
            return simple;
        }
        return resolveRuntime(token);
    }

    /**
     * 跨轮分片占位：{@code <<RUNTIME:<codec>:<param>...:partN>>}。
     * Runner 先编码完整密钥串，再按 part1/part2 切两半，使去空白拼接窗口能重组出完整串。
     */
    private String resolveRuntime(String token) {
        String body = token.substring(2, token.length() - 2); // 去 << >>
        String[] parts = body.split(":");
        if (parts.length < 2 || !"RUNTIME".equals(parts[0])) {
            throw new IllegalArgumentException("unknown runtime token: " + token);
        }
        String partTag = parts[parts.length - 1];
        String full = encodeFor(parts);
        if ("part1".equals(partTag)) {
            return full.substring(0, full.length() / 2);
        }
        if ("part2".equals(partTag)) {
            return full.substring(full.length() / 2);
        }
        return full;
    }

    /** RUNTIME 记号 → 完整编码串（不切片）。 */
    private String encodeFor(String[] parts) {
        String codec = parts[1];
        String kind = parts.length > 2 ? parts[2] : "";
        return switch (codec) {
            case "base58check" -> switch (kind) {
                case "wif-mainnet" -> wifMainnet();
                case "solana-keypair" -> base58Of(64);
                default -> throw new IllegalArgumentException("unknown base58check kind: " + kind);
            };
            case "bech32" -> {
                int flag = parts.length > 3 && parts[3].endsWith("01") ? 0x01 : 0x00;
                yield suiPrivkey(flag);
            }
            default -> throw new IllegalArgumentException("unknown runtime codec: " + codec);
        };
    }

    /** Base58Check 编码 N 字节全零 payload（无 checksum 语义，仅作 Base58 占位串）。 */
    private static String base58Of(int len) {
        return Base58Check.encode(new byte[len]);
    }

    // ===== WIF =====
    private static String wifMainnet() {
        return Base58Check.encode(concat(new byte[] {(byte) 0x80}, ZERO_32));
    }

    private static String wifCompressed() {
        return Base58Check.encode(concat(concat(new byte[] {(byte) 0x80}, ZERO_32), new byte[] {0x01}));
    }

    // ===== Solana 64 整数数组字面量 =====
    private static String solanaKeypairArray() {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < 64; i++) {
            if (i > 0) {
                sb.append(",");
            }
            sb.append("0");
        }
        return sb.append("]").toString();
    }

    // ===== Stellar StrKey：version 0x90 + 32 字节零 + CRC16-XModem(前33字节) =====
    private static String stellarSeed() {
        byte[] payload = new byte[33];
        payload[0] = STELLAR_SEED_VERSION;
        int crc = crc16XModem(payload);
        byte[] full = new byte[35];
        System.arraycopy(payload, 0, full, 0, 33);
        full[33] = (byte) (crc & 0xff);
        full[34] = (byte) ((crc >>> 8) & 0xff);
        return base32NoPad(full);
    }

    private static String base32NoPad(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int acc = 0;
        int bits = 0;
        for (byte b : data) {
            acc = (acc << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                sb.append(BASE32.charAt((acc >>> bits) & 31));
            }
        }
        if (bits > 0) {
            sb.append(BASE32.charAt((acc << (5 - bits)) & 31));
        }
        return sb.toString();
    }

    private static int crc16XModem(byte[] data) {
        int crc = 0x0000;
        for (byte datum : data) {
            crc ^= (datum & 0xff) << 8;
            for (int b = 0; b < 8; b++) {
                crc = ((crc & 0x8000) != 0) ? ((crc << 1) ^ 0x1021) : (crc << 1);
                crc &= 0xffff;
            }
        }
        return crc;
    }

    // ===== Sui suiprivkey Bech32：hrp=suiprivkey, data=convertBits(flag‖32零, 8,5,true) =====
    private static String suiPrivkey(int flag) {
        byte[] raw = new byte[33];
        raw[0] = (byte) flag;
        byte[] data = Bech32.convertBits(raw, 8, 5, true);
        return bech32Encode("suiprivkey", data);
    }

    private static String bech32Encode(String hrp, byte[] data) {
        byte[] checksum = bech32Checksum(hrp, data);
        StringBuilder sb = new StringBuilder(hrp).append('1');
        for (byte b : data) {
            sb.append(BECH32_CHARSET.charAt(b));
        }
        for (byte b : checksum) {
            sb.append(BECH32_CHARSET.charAt(b));
        }
        return sb.toString();
    }

    private static byte[] bech32Checksum(String hrp, byte[] data) {
        int[] expanded = bech32HrpExpand(hrp);
        int[] values = new int[expanded.length + data.length + 6];
        System.arraycopy(expanded, 0, values, 0, expanded.length);
        for (int i = 0; i < data.length; i++) {
            values[expanded.length + i] = data[i];
        }
        int polymod = bech32Polymod(values) ^ 1; // BECH32_CONST = 1
        byte[] checksum = new byte[6];
        for (int i = 0; i < 6; i++) {
            checksum[i] = (byte) ((polymod >>> (5 * (5 - i))) & 31);
        }
        return checksum;
    }

    private static int[] bech32HrpExpand(String hrp) {
        int[] out = new int[hrp.length() * 2 + 1];
        for (int i = 0; i < hrp.length(); i++) {
            out[i] = hrp.charAt(i) >>> 5;
            out[hrp.length() + 1 + i] = hrp.charAt(i) & 31;
        }
        return out;
    }

    private static int bech32Polymod(int[] values) {
        int chk = 1;
        for (int v : values) {
            int top = chk >>> 25;
            chk = (chk & 0x1ffffff) << 5 ^ v;
            for (int i = 0; i < 5; i++) {
                chk ^= ((top >>> i) & 1) != 0 ? BECH32_GENERATOR[i] : 0;
            }
        }
        return chk;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
