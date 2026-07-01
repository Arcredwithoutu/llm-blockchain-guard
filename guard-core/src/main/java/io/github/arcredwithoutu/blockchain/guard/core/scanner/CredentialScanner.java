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
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.EntropyScorer;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 应用凭据扫描器：API Key / PASSWORD（字段名命中）/ JWT。正则底座复用 gitleaks 规则（R2）。
 *
 * <p>关键设计：OpenAI key 用带 {@code T3BlbkFJ} 锚点的 regex（不用裸 {@code sk-} 前缀，误报高）；
 * generic-api-key 用「字段名 + 高熵值」兜底（{@link EntropyScorer}）。</p>
 */
public final class CredentialScanner implements GuardScanner {

    private static final String NAME = "credential";
    // generic-api-key 高熵兜底阈值（bits/char）。
    private static final double GENERIC_ENTROPY_THRESHOLD = 3.5;
    private static final int GENERIC_MIN_LEN = 16;

    // —— gitleaks 风格 API Key 正则底座（R2）——
    private static final Pattern AWS_AKIA = Pattern.compile("AKIA[0-9A-Z]{16}");
    private static final Pattern GCP_AIZA = Pattern.compile("AIza[0-9A-Za-z_\\-]{35}");
    private static final Pattern GITHUB_PAT = Pattern.compile("ghp_[0-9A-Za-z]{36}");
    private static final Pattern AGE_SECRET = Pattern.compile("AGE-SECRET-KEY-1[0-9A-Z]{58}");
    // OpenAI：以 T3BlbkFJ 为锚点（base64 of "OpenAI"），避免裸 sk- 高误报。
    private static final Pattern OPENAI_KEY = Pattern.compile("sk-[A-Za-z0-9_\\-]+T3BlbkFJ[A-Za-z0-9_\\-]+");
    // JWT：三段 base64url，header/payload 段以 ey 起头并设最小长度门槛（R2），避免 eyJa.b.c 短串误命中。
    private static final Pattern JWT = Pattern.compile(
            "ey[A-Za-z0-9]{17,}\\.ey[A-Za-z0-9/_\\-]{17,}\\.(?:[A-Za-z0-9/_\\-]{10,}={0,2})?");
    // generic-api-key：字段名（api[_-]?key/token/secret/access[_-]?key）+ 引号包裹的高熵值。
    private static final Pattern GENERIC_API_KEY = Pattern.compile(
            "(?i)(?:api[_-]?key|access[_-]?key|secret[_-]?key|token|secret)[\"'\\s]*[:=][\"'\\s]*"
                    + "([A-Za-z0-9_\\-./+]{" + GENERIC_MIN_LEN + ",})");
    // PASSWORD：字段名命中 → 整值替换；值非空白。
    private static final Pattern PASSWORD_FIELD = Pattern.compile(
            "(?i)(?:password|passwd|pwd)[\"'\\s]*[:=][\"'\\s]*(\\S+)");

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
        scanKeyword(findings, text, AWS_AKIA, GuardEntityType.API_KEY, "aws-access-key", 0.95);
        scanKeyword(findings, text, GCP_AIZA, GuardEntityType.API_KEY, "gcp-api-key", 0.9);
        scanKeyword(findings, text, GITHUB_PAT, GuardEntityType.API_KEY, "github-pat", 0.95);
        scanKeyword(findings, text, AGE_SECRET, GuardEntityType.API_KEY, "age-secret-key", 0.95);
        scanKeyword(findings, text, OPENAI_KEY, GuardEntityType.API_KEY, "openai-key", 0.9);
        scanKeyword(findings, text, JWT, GuardEntityType.JWT, "jwt", 0.85);
        scanCapturedValue(findings, text, PASSWORD_FIELD, GuardEntityType.PASSWORD, "password-field",
                GuardRiskLevel.HIGH, 0.9, false);
        scanCapturedValue(findings, text, GENERIC_API_KEY, GuardEntityType.API_KEY, "generic-api-key",
                GuardRiskLevel.MEDIUM, 0.6, true);
        return findings;
    }

    /** 整匹配作为 secret span（API Key / JWT）。 */
    private static void scanKeyword(List<GuardFinding> findings, String text, Pattern pattern,
            GuardEntityType type, String ruleId, double confidence) {
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            findings.add(new GuardFinding(type, GuardRiskLevel.HIGH, confidence,
                    m.start(), m.end(), ruleId, "matched " + ruleId + " pattern", null));
        }
    }

    /** 取捕获组 1（字段值）作为 secret span；generic 时附加高熵校验降误报。 */
    private static void scanCapturedValue(List<GuardFinding> findings, String text, Pattern pattern,
            GuardEntityType type, String ruleId, GuardRiskLevel risk, double confidence, boolean requireEntropy) {
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            String value = m.group(1);
            if (requireEntropy && EntropyScorer.shannon(value) < GENERIC_ENTROPY_THRESHOLD) {
                continue;
            }
            findings.add(new GuardFinding(type, risk, confidence,
                    m.start(1), m.end(1), ruleId, "matched " + ruleId + " field value", null));
        }
    }
}
