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

package io.github.arcredwithoutu.blockchain.guard.core.scanner;

import io.github.arcredwithoutu.blockchain.guard.core.api.GuardScanner;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.BlockchainSecretDetector;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.RuleMatch;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import io.github.arcredwithoutu.blockchain.guard.core.text.StructuredTextExtractor;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * 链上密钥扫描器：包装 {@link BlockchainSecretDetector}，把 {@link RuleMatch} 转 {@link GuardFinding}
 * （fingerprint 留 null，mask 阶段补）。
 *
 * <p>结合 {@link StructuredTextExtractor}：当输入为合法 JSON 时，对每个 string field value 单独扫描，
 * 并把命中 span <b>映射回原文偏移</b>（保结构换值）；同时对整段原文做一次全文扫描以覆盖跨字段/裸文本场景。
 * 两路命中按原文 span 去重。</p>
 */
public final class BlockchainSecretScanner implements GuardScanner {

    private static final String NAME = "blockchain-secret";

    private final BlockchainSecretDetector detector;

    public BlockchainSecretScanner(BlockchainSecretDetector detector) {
        this.detector = Objects.requireNonNull(detector, "detector");
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean supports(GuardContext ctx) {
        return true;
    }

    @Override
    public List<GuardFinding> scan(String text, GuardContext ctx) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        List<GuardFinding> findings = new ArrayList<>();
        List<int[]> spans = new ArrayList<>();
        // 1) 全文扫描（覆盖裸文本与跨字段拼接）。
        for (RuleMatch match : detector.detect(text, ctx)) {
            addUnique(findings, spans, toFinding(match, 0));
        }
        // 2) JSON 字段级扫描：value 子串 + 字段路径派生的上下文一并送检（设计 §4.2「字段名命中」），
        //    命中 span 映射回原文偏移；字段名仅作上下文增强，value 仍需匹配某条私钥规则才命中。
        List<StructuredTextExtractor.Field> fields = StructuredTextExtractor.extract(text);
        if (isStructured(fields)) {
            for (StructuredTextExtractor.Field field : fields) {
                scanFieldValue(field, ctx, findings, spans);
            }
        }
        return findings;
    }

    /**
     * 扫描单个字段 value：把字段路径派生的上下文词拼到 value 前作合成串送检，使敏感字段名
     * （private_key / wallet.key / secretKey…）为缺独立上下文的密钥提供正向上下文（设计 §4.2）。
     * 命中 span 减前缀长、加 valueStart 映射回原文；落在前缀内的命中丢弃（仅取 value 区域）。
     */
    private void scanFieldValue(StructuredTextExtractor.Field field, GuardContext ctx,
            List<GuardFinding> findings, List<int[]> spans) {
        String value = field.value();
        if (value == null || value.isEmpty()) {
            return;
        }
        String context = fieldNameContext(field);
        if (context.isEmpty()) {
            for (RuleMatch match : detector.detect(value, ctx)) {
                addUnique(findings, spans, toFinding(match, field.valueStart()));
            }
            return;
        }
        String prefix = context + ' ';
        int prefixLen = prefix.length();
        int offset = field.valueStart() - prefixLen;
        for (RuleMatch match : detector.detect(prefix + value, ctx)) {
            if (match.start() < prefixLen) {
                continue;
            }
            addUnique(findings, spans, toFinding(match, offset));
        }
    }

    /**
     * 由字段路径（无则用键名）派生空格分隔的小写上下文词：拆 camelCase 边界与 snake/kebab/dot/
     * 数组下标分隔符，使 private_key→"private key"、privateKey→"private key"、wallet.key→"wallet key"，
     * 与既有正向/负向上下文词表对齐。数组元素 / 全文 fallback 无可用名时返回空串（退回仅扫 value）。
     */
    private static String fieldNameContext(StructuredTextExtractor.Field field) {
        String raw = field.path() != null ? field.path() : field.key();
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        return raw
                .replaceAll("([a-z0-9])([A-Z])", "$1 $2")
                .replaceAll("[._\\-\\[\\]]+", " ")
                .trim()
                .replaceAll("\\s+", " ")
                .toLowerCase(Locale.ROOT);
    }

    /** 仅有一个 key==null 的全文 field 时视为非结构化，跳过字段级二次扫描（避免重复）。 */
    private static boolean isStructured(List<StructuredTextExtractor.Field> fields) {
        return !(fields.size() == 1 && fields.get(0).key() == null);
    }

    private static GuardFinding toFinding(RuleMatch match, int offset) {
        return new GuardFinding(match.entityType(), match.riskLevel(), match.confidence(),
                match.start() + offset, match.end() + offset, match.ruleId(), match.reason(), null);
    }

    /**
     * 去重：span 重叠且 entityType 相同即视为同一命中（全文路径带 0x 前缀、字段路径不带，span 不同但指向同一私钥），
     * 保留更大 span 者（覆盖更全，mask 时残留风险更低）。
     */
    private static void addUnique(List<GuardFinding> findings, List<int[]> spans, GuardFinding candidate) {
        for (int i = 0; i < spans.size(); i++) {
            int[] span = spans.get(i);
            boolean overlaps = candidate.start() < span[1] && span[0] < candidate.end();
            if (overlaps && findings.get(i).entityType() == candidate.entityType()) {
                int existingLen = span[1] - span[0];
                int candidateLen = candidate.end() - candidate.start();
                if (candidateLen > existingLen) {
                    spans.set(i, new int[] {candidate.start(), candidate.end()});
                    findings.set(i, candidate);
                }
                return;
            }
        }
        spans.add(new int[] {candidate.start(), candidate.end()});
        findings.add(candidate);
    }
}
