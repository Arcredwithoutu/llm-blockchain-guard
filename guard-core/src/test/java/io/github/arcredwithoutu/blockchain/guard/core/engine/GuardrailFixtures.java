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

import io.github.arcredwithoutu.blockchain.guard.core.api.GuardScanner;
import io.github.arcredwithoutu.blockchain.guard.core.api.GuardrailService;
import io.github.arcredwithoutu.blockchain.guard.core.api.ScannerRegistry;
import io.github.arcredwithoutu.blockchain.guard.core.audit.GuardAuditSink;
import io.github.arcredwithoutu.blockchain.guard.core.audit.LoggingGuardAuditSink;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.Bip39MnemonicRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.BitcoinWifRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.BlockchainSecretDetector;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.CardanoSigningKeyRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.DetectionRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.EvmPrivateKeyHexRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.ExtendedKeyRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.KeystoreJsonRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.PemPrivateKeyRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.SolanaKeypairRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.StellarSeedRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.SubstrateSecretUriRule;
import io.github.arcredwithoutu.blockchain.guard.core.blockchain.SuiPrivateKeyRule;
import io.github.arcredwithoutu.blockchain.guard.core.mask.FingerprintService;
import io.github.arcredwithoutu.blockchain.guard.core.mask.GuardMasker;
import io.github.arcredwithoutu.blockchain.guard.core.policy.DefaultGuardPolicyEngine;
import io.github.arcredwithoutu.blockchain.guard.core.policy.GuardPolicyConfig;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.BlockchainSecretScanner;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.CredentialScanner;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.PiiScanner;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.PromptInjectionScanner;
import java.util.List;

/**
 * 测试工具：手工 new 全套内核组件并组装 {@link DefaultGuardrailService}，
 * 证明 guard-core 可<b>脱离 Spring</b>构造（无 @Component、无容器）。
 *
 * <p>供下游项目的集成测试直接使用，无需自行装配全套管线。</p>
 */
public final class GuardrailFixtures {

    private GuardrailFixtures() {
    }

    /** 手工组装内核总入口：detector(11 规则) + registry(5 scanner) + merger + policy + masker + logging sink。 */
    public static GuardrailService defaultService(String pepper) {
        return defaultService(pepper, new LoggingGuardAuditSink());
    }

    /** 同上但可注入自定义审计 sink（用于验证审计异常被引擎吞掉、不破坏主链路）。 */
    public static GuardrailService defaultService(String pepper, GuardAuditSink auditSink) {
        BlockchainSecretDetector detector = new BlockchainSecretDetector(allRules());
        FingerprintService fingerprintService = new FingerprintService(pepper);
        ScannerRegistry registry = new DefaultScannerRegistry(scanners(detector));
        GuardMasker masker = new GuardMasker(fingerprintService);
        DefaultGuardPolicyEngine policyEngine = new DefaultGuardPolicyEngine(GuardPolicyConfig.defaults());
        return new DefaultGuardrailService(detector, registry, policyEngine, masker, auditSink, fingerprintService);
    }

    /** 以自定义 {@link ScannerRegistry} 组装内核（detector 空规则、无 preScrub），用于精确构造重叠命中场景。 */
    public static GuardrailService serviceWith(ScannerRegistry registry) {
        BlockchainSecretDetector detector = new BlockchainSecretDetector(List.of());
        FingerprintService fingerprintService = new FingerprintService("unit-pepper");
        GuardMasker masker = new GuardMasker(fingerprintService);
        DefaultGuardPolicyEngine policyEngine = new DefaultGuardPolicyEngine(GuardPolicyConfig.defaults());
        return new DefaultGuardrailService(detector, registry, policyEngine, masker,
                new LoggingGuardAuditSink(), fingerprintService);
    }

    /** 全部 11 条确定性私钥检测规则。 */
    private static List<DetectionRule> allRules() {
        return List.of(
                new EvmPrivateKeyHexRule(true),
                new Bip39MnemonicRule(List.of("english"), true),
                new BitcoinWifRule(),
                new ExtendedKeyRule(),
                new SolanaKeypairRule(),
                new SuiPrivateKeyRule(),
                new SubstrateSecretUriRule(),
                new CardanoSigningKeyRule(),
                new StellarSeedRule(),
                new KeystoreJsonRule(),
                new PemPrivateKeyRule());
    }

    /** 有序扫描器列表：Blockchain → Credential → Pii(本地 true) → PromptInjection(占位 false)。 */
    private static List<GuardScanner> scanners(BlockchainSecretDetector detector) {
        return List.of(
                new BlockchainSecretScanner(detector),
                new CredentialScanner(),
                new PiiScanner(true),
                new PromptInjectionScanner(false));
    }
}
