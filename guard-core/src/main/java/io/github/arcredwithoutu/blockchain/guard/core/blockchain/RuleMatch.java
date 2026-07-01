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
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;

/**
 * 检测规则命中结果（值对象）。fingerprint 不在此阶段计算，于 mask 阶段补齐。
 *
 * @param entityType 命中的敏感实体类型
 * @param riskLevel  风险等级
 * @param confidence 置信度 [0,1]
 * @param start      命中 span 起始下标（含）
 * @param end        命中 span 结束下标（不含）
 * @param ruleId     产生该命中的规则标识
 * @param reason     判定依据的简述
 */
public record RuleMatch(GuardEntityType entityType, GuardRiskLevel riskLevel, double confidence,
        int start, int end, String ruleId, String reason) {
}
