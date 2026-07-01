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

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * 链上密钥检测聚合器：跑全部 {@link DetectionRule}，收集 {@link RuleMatch} 并按 {@code start} 排序返回。
 *
 * <p>作为确定性私钥规则的统一出口，供 {@code DefaultGuardrailService.localPreScrub} 做 CRITICAL 早停。</p>
 */
public final class BlockchainSecretDetector {

    private final List<DetectionRule> rules;

    public BlockchainSecretDetector(List<DetectionRule> rules) {
        this.rules = List.copyOf(Objects.requireNonNull(rules, "rules"));
    }

    /** 跑全部规则收集命中，按 span 起始下标升序返回（同 start 时不再二次排序，保持规则注册顺序）。 */
    public List<RuleMatch> detect(String text, GuardContext ctx) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        List<RuleMatch> matches = new ArrayList<>();
        for (DetectionRule rule : rules) {
            matches.addAll(rule.detect(text, ctx));
        }
        matches.sort(Comparator.comparingInt(RuleMatch::start));
        return matches;
    }
}
