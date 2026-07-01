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

package io.github.arcredwithoutu.blockchain.guard.core.policy;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardAction;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardDirection;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * 策略矩阵配置（设计 §7）：每个 {@link GuardEntityType} 对应一行 {@link DirectionPolicy}。
 *
 * <p>{@link #defaults()} 提供默认矩阵；starter/yaml 可覆盖（构造另一份 config 注入）。
 * 未在矩阵中显式登记的实体类型，回落 {@link #fallback}（默认 MASK，保守不放行）。</p>
 */
public final class GuardPolicyConfig {

    /** *_PERSIST 类方向集合（trace/snapshot/memory 落库）。 */
    private static final Map<GuardDirection, GuardAction> PERSIST_MASK = persistOverride(GuardAction.MASK);

    private final Map<GuardEntityType, DirectionPolicy> matrix;
    private final GuardAction fallback;

    public GuardPolicyConfig(Map<GuardEntityType, DirectionPolicy> matrix, GuardAction fallback) {
        this.matrix = new EnumMap<>(Objects.requireNonNull(matrix, "matrix"));
        this.fallback = Objects.requireNonNull(fallback, "fallback");
    }

    /** 默认决策矩阵（设计 §7 表）。 */
    public static GuardPolicyConfig defaults() {
        Map<GuardEntityType, DirectionPolicy> matrix = new EnumMap<>(GuardEntityType.class);

        // 私钥/助记词/扩展私钥/keystore/PEM/各链签名密钥：所有方向 BLOCK（CRITICAL 硬规则）。
        DirectionPolicy alwaysBlock = DirectionPolicy.uniform(GuardAction.BLOCK);
        for (GuardEntityType type : new GuardEntityType[] {
                GuardEntityType.BLOCKCHAIN_MNEMONIC, GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_HEX,
                GuardEntityType.BLOCKCHAIN_PRIVATE_KEY_WIF, GuardEntityType.BLOCKCHAIN_EXTENDED_PRIVATE_KEY,
                GuardEntityType.BLOCKCHAIN_KEYSTORE_JSON, GuardEntityType.BLOCKCHAIN_SOLANA_KEYPAIR,
                GuardEntityType.BLOCKCHAIN_SUI_PRIVKEY, GuardEntityType.BLOCKCHAIN_CARDANO_SIGNING_KEY,
                GuardEntityType.BLOCKCHAIN_SUBSTRATE_SECRET_URI, GuardEntityType.BLOCKCHAIN_STELLAR_SECRET_SEED,
                GuardEntityType.PEM_PRIVATE_KEY}) {
            matrix.put(type, alwaysBlock);
        }

        // 应用凭据 API_KEY/PASSWORD/JWT：流转方向 BLOCK，落库方向 MASK。
        DirectionPolicy credential = new DirectionPolicy(PERSIST_MASK, GuardAction.BLOCK);
        matrix.put(GuardEntityType.API_KEY, credential);
        matrix.put(GuardEntityType.PASSWORD, credential);
        matrix.put(GuardEntityType.JWT, credential);

        // 扩展公钥 xpub：MODEL_INPUT/USER_INPUT/INGESTION/TOOL ALLOW，MODEL_OUTPUT/落库 MASK_PARTIAL（→ MASK）。
        Map<GuardDirection, GuardAction> xpubOverride = persistOverride(GuardAction.MASK);
        xpubOverride.put(GuardDirection.MODEL_OUTPUT, GuardAction.MASK);
        matrix.put(GuardEntityType.BLOCKCHAIN_EXTENDED_PUBLIC_KEY,
                new DirectionPolicy(xpubOverride, GuardAction.ALLOW));

        // 地址 / tx hash：流转方向 ALLOW（公开非密材料），落库方向 MASK_PARTIAL（→ MASK）。
        DirectionPolicy identifier = new DirectionPolicy(PERSIST_MASK, GuardAction.ALLOW);
        matrix.put(GuardEntityType.BLOCKCHAIN_ADDRESS, identifier);
        matrix.put(GuardEntityType.BLOCKCHAIN_TX_HASH, identifier);

        // PII：所有方向 MASK。
        matrix.put(GuardEntityType.PII, DirectionPolicy.uniform(GuardAction.MASK));

        // PROMPT_INJECTION：移除攻击句（MASK 由 masker 替换为 [REMOVED_UNTRUSTED_INSTRUCTION]）。
        matrix.put(GuardEntityType.PROMPT_INJECTION, DirectionPolicy.uniform(GuardAction.MASK));

        return new GuardPolicyConfig(matrix, GuardAction.MASK);
    }

    /** 取实体类别的方向策略；未登记类别返回 {@code null}（由引擎落 fallback）。 */
    public DirectionPolicy policyFor(GuardEntityType entityType) {
        return matrix.get(entityType);
    }

    public GuardAction fallback() {
        return fallback;
    }

    /** 构造 trace/snapshot/memory 三种落库方向的统一 override map。 */
    private static Map<GuardDirection, GuardAction> persistOverride(GuardAction action) {
        Map<GuardDirection, GuardAction> map = new EnumMap<>(GuardDirection.class);
        map.put(GuardDirection.TRACE_PERSIST, action);
        map.put(GuardDirection.SNAPSHOT_PERSIST, action);
        map.put(GuardDirection.MEMORY_PERSIST, action);
        return map;
    }
}
