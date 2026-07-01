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

package io.github.arcredwithoutu.blockchain.guard.core.model;

public enum GuardEntityType {
    BLOCKCHAIN_MNEMONIC, BLOCKCHAIN_PRIVATE_KEY_HEX, BLOCKCHAIN_PRIVATE_KEY_WIF,
    BLOCKCHAIN_EXTENDED_PRIVATE_KEY, BLOCKCHAIN_EXTENDED_PUBLIC_KEY, BLOCKCHAIN_KEYSTORE_JSON,
    BLOCKCHAIN_SOLANA_KEYPAIR, BLOCKCHAIN_SUI_PRIVKEY, BLOCKCHAIN_CARDANO_SIGNING_KEY,
    BLOCKCHAIN_SUBSTRATE_SECRET_URI, BLOCKCHAIN_STELLAR_SECRET_SEED,
    BLOCKCHAIN_ADDRESS, BLOCKCHAIN_TX_HASH,
    API_KEY, PASSWORD, JWT, PEM_PRIVATE_KEY, PII, PROMPT_INJECTION
}
