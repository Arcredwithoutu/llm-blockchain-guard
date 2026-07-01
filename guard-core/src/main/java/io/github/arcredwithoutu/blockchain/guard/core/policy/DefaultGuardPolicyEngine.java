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
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import java.util.Objects;

/**
 * 默认策略引擎（设计 §7）：由 {@link GuardPolicyConfig} 矩阵驱动。
 *
 * <p>硬规则优先：CRITICAL 风险的私钥类实体（含助记词/keystore/PEM）在<b>所有方向</b> BLOCK，
 * 不受矩阵配置覆盖影响；其余按 方向 × 实体 查矩阵，未登记类别落 {@code fallback}。</p>
 */
public final class DefaultGuardPolicyEngine implements GuardPolicyEngine {

    private final GuardPolicyConfig config;

    public DefaultGuardPolicyEngine(GuardPolicyConfig config) {
        this.config = Objects.requireNonNull(config, "config");
    }

    @Override
    public GuardAction decide(GuardEntityType entityType, GuardDirection direction,
            GuardRiskLevel riskLevel, double confidence) {
        // 硬规则（§7）：CRITICAL 的确定性私钥类实体在所有方向无条件 BLOCK，凌驾于 config 矩阵之上、不受其放宽。
        // 注意只锁 CRITICAL：HIGH/MEDIUM/LOW 的低置信度私钥类（如 §6.2 无上下文 64hex→MEDIUM、
        // 64hex+tx_hash/sha256 上下文→LOW/忽略）有意按 config 矩阵走、可配置（避免把链上分析要放行的
        // tx hash 全部误阻断）；这类低置信度的精度调优在批次三红队完成。
        if (riskLevel == GuardRiskLevel.CRITICAL && isPrivateKeyClass(entityType)) {
            return GuardAction.BLOCK;
        }
        DirectionPolicy policy = config.policyFor(entityType);
        if (policy == null) {
            return config.fallback();
        }
        return policy.actionFor(direction);
    }

    /** 是否属于「绝不可泄露」的私钥类实体（CRITICAL 时触发全方向 BLOCK 硬规则）。 */
    private static boolean isPrivateKeyClass(GuardEntityType type) {
        return switch (type) {
            case BLOCKCHAIN_MNEMONIC, BLOCKCHAIN_PRIVATE_KEY_HEX, BLOCKCHAIN_PRIVATE_KEY_WIF,
                    BLOCKCHAIN_EXTENDED_PRIVATE_KEY, BLOCKCHAIN_KEYSTORE_JSON, BLOCKCHAIN_SOLANA_KEYPAIR,
                    BLOCKCHAIN_SUI_PRIVKEY, BLOCKCHAIN_CARDANO_SIGNING_KEY, BLOCKCHAIN_SUBSTRATE_SECRET_URI,
                    BLOCKCHAIN_STELLAR_SECRET_SEED, PEM_PRIVATE_KEY ->
                true;
            default -> false;
        };
    }
}
