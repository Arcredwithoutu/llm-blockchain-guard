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

package io.github.arcredwithoutu.blockchain.guard.spring;

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
import io.github.arcredwithoutu.blockchain.guard.core.engine.DefaultGuardrailService;
import io.github.arcredwithoutu.blockchain.guard.core.engine.DefaultScannerRegistry;
import io.github.arcredwithoutu.blockchain.guard.core.mask.FingerprintService;
import io.github.arcredwithoutu.blockchain.guard.core.mask.GuardMasker;
import io.github.arcredwithoutu.blockchain.guard.core.policy.DefaultGuardPolicyEngine;
import io.github.arcredwithoutu.blockchain.guard.core.policy.GuardPolicyConfig;
import io.github.arcredwithoutu.blockchain.guard.core.policy.GuardPolicyEngine;
import io.github.arcredwithoutu.blockchain.guard.core.provider.CircuitBreakingProviderClient;
import io.github.arcredwithoutu.blockchain.guard.core.provider.GuardProviderClient;
import io.github.arcredwithoutu.blockchain.guard.core.provider.LlmGuardClient;
import io.github.arcredwithoutu.blockchain.guard.core.provider.PresidioGuardClient;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.BlockchainAddressScanner;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.BlockchainSecretScanner;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.CredentialScanner;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.PiiScanner;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.PromptInjectionScanner;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.ProviderInjectionScanner;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.ProviderPiiScanner;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Guard 模块自动装配：按 {@link GuardProperties} 手工组装全套 guard-core POJO 为 Spring bean。
 *
 * <p>装配链：11 条 {@link DetectionRule} → {@link BlockchainSecretDetector} → 4 个 {@link GuardScanner}
 * → {@link ScannerRegistry}；{@link GuardPolicyEngine}（默认策略矩阵）、{@link FingerprintService}（pepper
 * 取自 {@code audit.hmac-pepper-env} 指向的环境变量）、{@link GuardMasker}、{@link GuardAuditSink}（默认
 * logging，允许应用覆盖为 MySQL）→ 汇成 {@link GuardrailService}。
 *
 * <p>本地 PII 由 {@code pii.enabled} 控制；远程 {@link ProviderPiiScanner}（Presidio）按 {@code pii.provider-enabled}
 * 条件装配并并列注入 registry，命中由 SpanMerger 与本地合并去重。LLM Guard client 按 {@code prompt-injection.enabled}
 * 条件装配，供后续批次注入扫描器。
 */
@Slf4j
@AutoConfiguration
@EnableConfigurationProperties(GuardProperties.class)
@ConditionalOnProperty(prefix = "rag.guard", name = "enabled", havingValue = "true", matchIfMissing = true)
public class GuardAutoConfiguration {

    /** pepper 环境变量缺失时的占位默认值，保证启动不失败（仅审计指纹加盐，非密钥）。 */
    private static final String FALLBACK_AUDIT_PEPPER = "guard-default-pepper";

    @Bean
    @ConditionalOnMissingBean
    public BlockchainSecretDetector blockchainSecretDetector(GuardProperties properties) {
        GuardProperties.LocalSecret localSecret = properties.getLocalSecret();
        List<DetectionRule> rules = List.of(
                new Bip39MnemonicRule(localSecret.getBip39Languages(), localSecret.isCheckBip39Checksum()),
                new EvmPrivateKeyHexRule(localSecret.isSecp256k1HexContextRequired()),
                new BitcoinWifRule(),
                new ExtendedKeyRule(),
                new SolanaKeypairRule(),
                new SuiPrivateKeyRule(),
                new SubstrateSecretUriRule(),
                new CardanoSigningKeyRule(),
                new StellarSeedRule(),
                new KeystoreJsonRule(),
                new PemPrivateKeyRule());
        return new BlockchainSecretDetector(rules);
    }

    @Bean
    @ConditionalOnMissingBean
    public ScannerRegistry guardScannerRegistry(BlockchainSecretDetector detector, GuardProperties properties,
            ObjectProvider<ProviderPiiScanner> providerPiiScanner,
            ObjectProvider<ProviderInjectionScanner> providerInjectionScanner) {
        List<GuardScanner> scanners = new ArrayList<>();
        scanners.add(new BlockchainSecretScanner(detector));
        scanners.add(new BlockchainAddressScanner());
        scanners.add(new CredentialScanner());
        scanners.add(new PiiScanner(properties.getPii().isEnabled()));
        scanners.add(new PromptInjectionScanner(properties.getPromptInjection().isEnabled()));
        // 远程 Presidio PII 扫描器仅当 pii.provider-enabled=true 才有 bean；命中由 SpanMerger 与本地合并去重。
        providerPiiScanner.ifAvailable(scanners::add);
        // 远程 LLM Guard 注入扫描器仅当 prompt-injection.provider-enabled=true 才有 bean。
        providerInjectionScanner.ifAvailable(scanners::add);
        return new DefaultScannerRegistry(scanners);
    }

    @Bean
    @ConditionalOnMissingBean
    public GuardPolicyEngine guardPolicyEngine() {
        return new DefaultGuardPolicyEngine(GuardPolicyConfig.defaults());
    }

    @Bean
    @ConditionalOnMissingBean
    public FingerprintService guardFingerprintService(GuardProperties properties) {
        String pepper = resolveAuditPepper(properties.getAudit().getHmacPepperEnv());
        return new FingerprintService(pepper);
    }

    @Bean
    @ConditionalOnMissingBean
    public GuardMasker guardMasker(FingerprintService fingerprintService) {
        return new GuardMasker(fingerprintService);
    }

    @Bean
    @ConditionalOnMissingBean
    public GuardAuditSink guardAuditSink() {
        return new LoggingGuardAuditSink();
    }

    @Bean
    @ConditionalOnMissingBean
    public GuardrailService guardrailService(BlockchainSecretDetector detector, ScannerRegistry scannerRegistry,
            GuardPolicyEngine policyEngine, GuardMasker masker, GuardAuditSink auditSink,
            FingerprintService fingerprintService) {
        return new DefaultGuardrailService(detector, scannerRegistry, policyEngine, masker, auditSink,
                fingerprintService);
    }

    /**
     * Presidio PII provider 扫描器：仅当 {@code pii.provider-enabled=true} 装配。客户端按 {@code pii.timeout-ms}
     * 超时降级，可选 {@link CircuitBreakingProviderClient} 熔断；并列注入 {@link #guardScannerRegistry}，
     * 命中由 SpanMerger 与本地 PII 合并去重。
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "rag.guard.pii", name = "provider-enabled", havingValue = "true")
    public ProviderPiiScanner providerPiiScanner(GuardProperties properties) {
        GuardProperties.Pii pii = properties.getPii();
        GuardProviderClient client = new PresidioGuardClient(pii.getEndpoint(), pii.getLanguage(), pii.getTimeoutMs());
        if (pii.isCircuitBreaker()) {
            client = new CircuitBreakingProviderClient(client, pii.getCircuitBreakerFailureThreshold(),
                    pii.getTimeoutMs(), pii.getCircuitBreakerCooldownMs());
        }
        return new ProviderPiiScanner(client, true, pii.getMinScore(), new HashSet<>(pii.getAllowedTypes()));
    }

    /**
     * LLM Guard prompt-injection provider 扫描器：仅当 {@code prompt-injection.provider-enabled=true} 装配。
     * client 按 {@code prompt-injection.timeout-ms} 超时降级，可选 {@link CircuitBreakingProviderClient} 熔断；
     * 并列注入 {@link #guardScannerRegistry}，与本地 {@link PromptInjectionScanner} 互补。
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "rag.guard.prompt-injection", name = "provider-enabled", havingValue = "true")
    public ProviderInjectionScanner providerInjectionScanner(GuardProperties properties) {
        GuardProperties.PromptInjection pi = properties.getPromptInjection();
        GuardProviderClient client = new LlmGuardClient(pi.getEndpoint(), pi.getMinScore(), pi.getTimeoutMs());
        if (pi.isCircuitBreaker()) {
            client = new CircuitBreakingProviderClient(client, pi.getCircuitBreakerFailureThreshold(),
                    pi.getTimeoutMs(), pi.getCircuitBreakerCooldownMs());
        }
        return new ProviderInjectionScanner(client, true, pi.getMinScore());
    }

    /** 从环境变量取 pepper；缺失时返回非空默认值并告警，避免启动失败（设计 §12）。 */
    private String resolveAuditPepper(String envName) {
        String pepper = envName == null ? null : System.getenv(envName);
        if (pepper == null || pepper.isBlank()) {
            log.warn("Guard audit pepper env [{}] is missing; using fallback pepper. "
                    + "Set it in production to harden fingerprint salting.", envName);
            return FALLBACK_AUDIT_PEPPER;
        }
        return pepper;
    }
}
