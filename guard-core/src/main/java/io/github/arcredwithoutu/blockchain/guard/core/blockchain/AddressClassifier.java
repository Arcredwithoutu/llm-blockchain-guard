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

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import java.util.regex.Pattern;

/**
 * 区分链上「公开标识」与私钥同形串：EVM 地址（0x+40hex）/ tx hash（0x+64hex）/ base58 比特币地址。
 * tx hash 与 64hex 私钥同形，靠上下文区分（本类只做形态分类，上下文判定交由规则层）。
 */
public final class AddressClassifier {

    private static final Pattern EVM_ADDRESS = Pattern.compile("(?i)^0x[0-9a-f]{40}$");
    private static final Pattern EVM_TX_HASH = Pattern.compile("(?i)^0x[0-9a-f]{64}$");
    // base58 比特币地址（P2PKH '1' / P2SH '3'），长度 26~35
    private static final Pattern BASE58_BTC = Pattern.compile("^[13][1-9A-HJ-NP-Za-km-z]{25,34}$");

    private AddressClassifier() {
    }

    /** 按形态分类公开链上标识；不匹配任何已知形态时返回 null。 */
    public static GuardEntityType classify(String token) {
        if (token == null || token.isEmpty()) {
            return null;
        }
        if (EVM_ADDRESS.matcher(token).matches() || BASE58_BTC.matcher(token).matches()) {
            return GuardEntityType.BLOCKCHAIN_ADDRESS;
        }
        if (EVM_TX_HASH.matcher(token).matches()) {
            return GuardEntityType.BLOCKCHAIN_TX_HASH;
        }
        return null;
    }
}
