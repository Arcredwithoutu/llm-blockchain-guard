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

package io.github.arcredwithoutu.blockchain.guard.core.audit;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardAction;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardDirection;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;

/**
 * 审计事件（字段对齐 {@code t_guard_event}）。<b>绝不承载原文</b>：敏感内容仅以 HMAC {@code fingerprint} 表征。
 *
 * @param direction      数据流方向
 * @param source         接缝来源标识（如 rag-chat / rag-trace）
 * @param entityType     命中的敏感实体类型
 * @param riskLevel      风险等级
 * @param confidence     置信度 [0,1]
 * @param action         最终处置动作
 * @param ruleId         命中规则标识
 * @param fingerprint    HMAC-SHA256 指纹（替代原文，不可逆推）
 * @param spanCount      本次决策合并后的命中 span 数
 * @param elapsedMs      检测耗时（毫秒）
 * @param traceId        链路追踪 ID
 * @param conversationId 会话 ID（可空）
 * @param userId         用户 ID（可空）
 * @param metadataJson   附加脱敏元数据 JSON（不含原文，可空）
 */
public record GuardEvent(GuardDirection direction, String source, GuardEntityType entityType,
        GuardRiskLevel riskLevel, double confidence, GuardAction action, String ruleId,
        String fingerprint, int spanCount, long elapsedMs, String traceId,
        String conversationId, String userId, String metadataJson) {
}
