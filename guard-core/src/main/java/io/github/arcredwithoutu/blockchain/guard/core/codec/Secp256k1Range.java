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

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import java.math.BigInteger;

public final class Secp256k1Range {
    private static final BigInteger N;
    static {
        X9ECParameters params = CustomNamedCurves.getByName("secp256k1");
        N = params.getN();
    }

    private Secp256k1Range() {
    }

    public static BigInteger order() { return N; }

    /** 合法私钥范围 1 ≤ k ≤ n-1。 */
    public static boolean isValidPrivateKey(BigInteger k) {
        return k != null && k.signum() > 0 && k.compareTo(N) < 0;
    }
}
