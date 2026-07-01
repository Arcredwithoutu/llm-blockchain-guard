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

package io.github.arcredwithoutu.blockchain.guard.core.engine;

import io.github.arcredwithoutu.blockchain.guard.core.api.GuardrailService;
import io.github.arcredwithoutu.blockchain.guard.core.api.ScannerRegistry;
import io.github.arcredwithoutu.blockchain.guard.core.audit.GuardAuditSink;
import io.github.arcredwithoutu.blockchain.guard.core.audit.GuardEvent;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.BlockchainSecretDetector;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.RuleMatch;
import io.github.arcredwithoutu.blockchain.guard.core.mask.FingerprintService;
import io.github.arcredwithoutu.blockchain.guard.core.mask.GuardMasker;
import io.github.arcredwithoutu.blockchain.guard.core.mask.SpanMerger;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardAction;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardDecision;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import io.github.arcredwithoutu.blockchain.guard.core.policy.GuardPolicyEngine;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 内核总入口默认实现（设计 §4.2）：纯 POJO 组装，<b>不依赖 Spring</b>。
 *
 * <p>执行管线：localPreScrub（CRITICAL 早停）→ {@code scannerRegistry.scanAll} → {@code SpanMerger.mergeWithinType}
 * （同类型去重、跨类型保留）→ 逐 finding {@code policyEngine.decide}（取最严 action）→ {@code masker.apply}
 * → {@code auditSink.record} → 返回 {@link GuardDecision}。BLOCK 时 {@code sanitizedText} 为安全提示、不回显原文。</p>
 */
public final class DefaultGuardrailService implements GuardrailService {

    private static final Logger LOGGER = Logger.getLogger(DefaultGuardrailService.class.getName());

    /** BLOCK 时对外返回的安全占位文本（不含任何原文片段）。 */
    private static final String BLOCKED_PLACEHOLDER = "[GUARD_BLOCKED: sensitive content removed]";
    /** BLOCK 时面向用户的友好提示。 */
    private static final String BLOCKED_USER_MESSAGE =
            "检测到敏感信息（如私钥/助记词/凭据），出于安全已阻断本次请求，请移除敏感内容后重试。";

    private final BlockchainSecretDetector detector;
    private final ScannerRegistry scannerRegistry;
    private final GuardPolicyEngine policyEngine;
    private final GuardMasker masker;
    private final GuardAuditSink auditSink;
    private final FingerprintService fingerprintService;

    public DefaultGuardrailService(BlockchainSecretDetector detector, ScannerRegistry scannerRegistry,
            GuardPolicyEngine policyEngine, GuardMasker masker, GuardAuditSink auditSink,
            FingerprintService fingerprintService) {
        this.detector = Objects.requireNonNull(detector, "detector");
        this.scannerRegistry = Objects.requireNonNull(scannerRegistry, "scannerRegistry");
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine");
        this.masker = Objects.requireNonNull(masker, "masker");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.fingerprintService = Objects.requireNonNull(fingerprintService, "fingerprintService");
    }

    @Override
    public GuardDecision inspect(String text, GuardContext ctx) {
        long startNanos = System.nanoTime();
        if (text == null || text.isEmpty()) {
            return new GuardDecision(GuardAction.ALLOW, text, List.of(), null, elapsedMs(startNanos));
        }
        // 1) localPreScrub：先查 CRITICAL secret（私钥/助记词/keystore），命中即早停 BLOCK，不再跑后续扫描。
        //    detect 只跑一次，结果复用给 blockedDecision，避免对长文本重复解码。
        List<RuleMatch> preScrubMatches = detector.detect(text, ctx);
        if (hasCriticalSecret(preScrubMatches)) {
            return blockedDecision(preScrubMatches, text, ctx, startNanos);
        }
        // 2) 全量扫描 → 同类型合并去重（跨 entityType 保留独立，避免整段注入吞并同句凭据/PII 致 BLOCK 降级与审计塌缩）。
        List<GuardFinding> merged = withFingerprints(text, SpanMerger.mergeWithinType(scannerRegistry.scanAll(text, ctx)));
        if (merged.isEmpty()) {
            return new GuardDecision(GuardAction.ALLOW, text, List.of(), null, elapsedMs(startNanos));
        }
        // 3) 逐 finding 决策，整体取最严 action。
        GuardAction overall = GuardAction.ALLOW;
        for (GuardFinding finding : merged) {
            GuardAction action = policyEngine.decide(finding.entityType(), ctx.direction(),
                    finding.riskLevel(), finding.confidence());
            overall = strictest(overall, action);
        }
        long elapsedMs = elapsedMs(startNanos);
        if (overall == GuardAction.BLOCK) {
            recordAudit(text, ctx, merged, GuardAction.BLOCK, elapsedMs);
            return new GuardDecision(GuardAction.BLOCK, BLOCKED_PLACEHOLDER, merged,
                    BLOCKED_USER_MESSAGE, elapsedMs);
        }
        // 4) MASK/REVIEW/ALLOW：ALLOW 直接放行原文；否则脱敏。
        String sanitized = overall == GuardAction.ALLOW ? text : masker.apply(text, merged);
        recordAudit(text, ctx, merged, overall, elapsedMs);
        return new GuardDecision(overall, sanitized, merged, null, elapsedMs);
    }

    /** localPreScrub：给定确定性私钥规则命中，存在 CRITICAL 即返回 true。 */
    private static boolean hasCriticalSecret(List<RuleMatch> matches) {
        for (RuleMatch match : matches) {
            if (match.riskLevel() == GuardRiskLevel.CRITICAL) {
                return true;
            }
        }
        return false;
    }

    /** CRITICAL 早停：复用 preScrub 命中转 finding、审计、返回 BLOCK（sanitizedText 为安全占位，不含原文）。 */
    private GuardDecision blockedDecision(List<RuleMatch> matches, String text, GuardContext ctx, long startNanos) {
        List<GuardFinding> findings = new ArrayList<>();
        for (RuleMatch match : matches) {
            findings.add(new GuardFinding(match.entityType(), match.riskLevel(), match.confidence(),
                    match.start(), match.end(), match.ruleId(), match.reason(), null));
        }
        // preScrub 仅产出私钥类 finding（同一 entityType 域），此处全合并等价于 mergeWithinType。
        List<GuardFinding> merged = withFingerprints(text, SpanMerger.merge(findings));
        long elapsedMs = elapsedMs(startNanos);
        recordAudit(text, ctx, merged, GuardAction.BLOCK, elapsedMs);
        return new GuardDecision(GuardAction.BLOCK, BLOCKED_PLACEHOLDER, merged,
                BLOCKED_USER_MESSAGE, elapsedMs);
    }

    /** 返回给 HTTP/service 调用方的 finding 也携带 HMAC 指纹，便于关联审计且不暴露原文。 */
    private List<GuardFinding> withFingerprints(String text, List<GuardFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            return List.of();
        }
        List<GuardFinding> enriched = new ArrayList<>(findings.size());
        for (GuardFinding finding : findings) {
            String fingerprint = finding.fingerprint();
            if (fingerprint == null || fingerprint.isEmpty()) {
                fingerprint = fingerprintFor(text, finding);
            }
            enriched.add(new GuardFinding(finding.entityType(), finding.riskLevel(), finding.confidence(),
                    finding.start(), finding.end(), finding.ruleId(), finding.reason(), fingerprint));
        }
        return enriched;
    }

    /**
     * 每个 finding 写一条审计事件，fingerprint 对原文 span 现算（HMAC，绝不放原文）。
     *
     * <p>结构保证「审计绝不破坏主流程」（§4.2）：吞掉 sink 抛出的 {@code RuntimeException}（如批次二
     * MySqlGuardAuditSink 的 DB 抖动），降级为 logging warning，使 inspect 主链路（尤其 BLOCK 路径）
     * 不被审计失败打断，也不会 fail-open。</p>
     */
    private void recordAudit(String text, GuardContext ctx, List<GuardFinding> findings,
            GuardAction action, long elapsedMs) {
        int spanCount = findings.size();
        for (GuardFinding finding : findings) {
            String fingerprint = fingerprintFor(text, finding);
            GuardEvent event = new GuardEvent(ctx.direction(), ctx.source(), finding.entityType(),
                    finding.riskLevel(), finding.confidence(), action, finding.ruleId(), fingerprint,
                    spanCount, elapsedMs, ctx.traceId(), ctx.conversationId(), ctx.userId(), null);
            try {
                auditSink.record(event);
            } catch (RuntimeException ex) {
                LOGGER.log(Level.WARNING, "guard audit sink failed, swallowed to protect main flow", ex);
            }
        }
    }

    /** 取 finding 自带 fingerprint；为空则对原文 span 现算 HMAC 指纹。 */
    private String fingerprintFor(String text, GuardFinding finding) {
        if (finding.fingerprint() != null && !finding.fingerprint().isEmpty()) {
            return finding.fingerprint();
        }
        int start = Math.max(0, finding.start());
        int end = Math.min(text.length(), finding.end());
        if (start >= end) {
            return null;
        }
        return fingerprintService.fingerprint8(text.substring(start, end));
    }

    /** 取最严动作：BLOCK > MASK > REVIEW > ALLOW。 */
    private static GuardAction strictest(GuardAction a, GuardAction b) {
        return severity(a) >= severity(b) ? a : b;
    }

    private static int severity(GuardAction action) {
        return switch (action) {
            case BLOCK -> 3;
            case MASK -> 2;
            case REVIEW -> 1;
            case ALLOW -> 0;
        };
    }

    private static long elapsedMs(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }
}
