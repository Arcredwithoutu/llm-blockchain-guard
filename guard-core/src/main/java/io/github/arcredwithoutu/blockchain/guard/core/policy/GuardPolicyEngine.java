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

/** 策略引擎 SPI（设计 §7）：按 方向 × 实体 × 风险 × 置信度 给出处置动作。 */
public interface GuardPolicyEngine {

    /**
     * 决策单条命中的处置动作。
     *
     * @param entityType 命中的敏感实体类型
     * @param direction  数据流方向（决定该实体在此场景的容忍度）
     * @param riskLevel  风险等级（CRITICAL 私钥类触发全方向 BLOCK 硬规则）
     * @param confidence 置信度 [0,1]
     * @return 处置动作 ALLOW/MASK/BLOCK/REVIEW
     */
    GuardAction decide(GuardEntityType entityType, GuardDirection direction,
            GuardRiskLevel riskLevel, double confidence);
}
