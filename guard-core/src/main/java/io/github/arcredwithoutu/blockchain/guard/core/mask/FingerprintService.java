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

package io.github.arcredwithoutu.blockchain.guard.core.mask;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import java.nio.charset.StandardCharsets;

/** HMAC-SHA256(rawSecret, pepper) → hex → 前 8/16 位。禁止裸 SHA256（设计 §5.2）。pepper 由构造注入。 */
public final class FingerprintService {

    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private final byte[] pepper;

    public FingerprintService(String pepper) {
        if (pepper == null || pepper.isBlank()) {
            throw new IllegalArgumentException("guard audit pepper must not be blank");
        }
        this.pepper = pepper.getBytes(StandardCharsets.UTF_8);
    }

    /** 取前 8 hex 字符（短指纹，审计/mask 用）。 */
    public String fingerprint8(String rawSecret) {
        return hmacHex(rawSecret).substring(0, 8);
    }

    /** 取前 16 hex 字符（去重用）。 */
    public String fingerprint16(String rawSecret) {
        return hmacHex(rawSecret).substring(0, 16);
    }

    private String hmacHex(String rawSecret) {
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(pepper));            // pepper 作 HMAC key
        byte[] msg = rawSecret.getBytes(StandardCharsets.UTF_8);
        hmac.update(msg, 0, msg.length);
        byte[] mac = new byte[hmac.getMacSize()];       // 32
        hmac.doFinal(mac, 0);
        StringBuilder sb = new StringBuilder(mac.length * 2);
        for (byte b : mac) {
            sb.append(HEX[(b >> 4) & 0xF]).append(HEX[b & 0xF]);
        }
        return sb.toString();
    }
}
