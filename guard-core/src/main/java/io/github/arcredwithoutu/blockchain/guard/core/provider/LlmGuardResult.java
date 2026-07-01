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

package io.github.arcredwithoutu.blockchain.guard.core.provider;

import java.util.List;
import java.util.Map;

/**
 * LLM Guard {@code /analyze/prompt} 响应（R3 坐实 {@code llm_guard_api/app/schemas.py}）：
 *
 * @param valid           {@code is_valid}：false 触发 BLOCK/REVIEW
 * @param scanners        各 scanner 名 → 风险分（缺失时为空 map）
 * @param sanitizedPrompt {@code sanitized_prompt}：清洗后文本（缺失时为 null）
 */
public record LlmGuardResult(boolean valid, Map<String, Double> scanners, String sanitizedPrompt) {

    public LlmGuardResult {
        scanners = scanners == null ? Map.of() : Map.copyOf(scanners);
    }

    /** 远程不可用时的安全降级值：valid=true（不误阻断）、无 scanner 命中、无清洗文本。 */
    public static LlmGuardResult passthrough() {
        return new LlmGuardResult(true, Map.of(), null);
    }

    /** 把超阈值的 scanner 映射成 {@link ProviderEntity}（span 未知置 -1，分值透传）。 */
    public List<ProviderEntity> toEntities(double scoreThreshold) {
        return scanners.entrySet().stream()
                .filter(entry -> entry.getValue() != null && entry.getValue() >= scoreThreshold)
                .map(entry -> new ProviderEntity(entry.getKey(), -1, -1, entry.getValue()))
                .toList();
    }
}
