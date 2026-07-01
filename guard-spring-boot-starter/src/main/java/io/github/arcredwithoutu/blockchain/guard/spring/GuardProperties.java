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

import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Guard 模块配置项（前缀 {@code rag.guard}，字段对齐设计 §12 配置总表）。
 *
 * <p>本类是 starter 中唯一的 Spring 配置绑定点；core 侧保持纯 POJO，由 {@link GuardAutoConfiguration}
 * 读取本类后转换注入，避免 guard-core 依赖 Spring。
 */
@Data
@ConfigurationProperties(prefix = "rag.guard")
public class GuardProperties {

    /** 总开关；关闭则整套自动装配回退（不注册 GuardrailService）。 */
    private boolean enabled = true;

    /** fail-closed 语义：检测异常时按阻断处理（保守优先）。 */
    private boolean failClosed = true;

    /** 单次扫描的最大字符数，超出截断（防超长文本拖垮检测）。 */
    private int maxScanChars = 200000;

    /** 本地确定性密钥检测配置（私钥/助记词/keystore 等）。 */
    private LocalSecret localSecret = new LocalSecret();

    /** 会话级跨轮累积检测配置（§8.9）。 */
    private ConversationWindow conversationWindow = new ConversationWindow();

    /** PII 检测配置（本地规则 + 可选 Presidio provider）。 */
    private Pii pii = new Pii();

    /** Prompt injection 检测配置（本地规则 + 可选 LLM Guard provider）。 */
    private PromptInjection promptInjection = new PromptInjection();

    /** 审计配置（仅落指纹，无原文）。 */
    private Audit audit = new Audit();

    @Data
    public static class LocalSecret {

        private boolean enabled = true;

        /**
         * BIP39 助记词词表语言。<b>出厂默认仅 english</b>：{@code chinese_simplified} 词表为单汉字，
         * 当前 {@code Bip39MnemonicRule} 逐字成 token + 仅 checksum 校验，会把普通中文散文误判为
         * 助记词并阻断（验收 findings G1，2026-06-16）。需中文助记词检测者可显式配
         * {@code [english, chinese_simplified]} 开启（接受散文误报风险，待中文上下文门控修复后恢复默认）。
         */
        private List<String> bip39Languages = List.of("english");

        private boolean checkBip39Checksum = true;

        private boolean secp256k1HexContextRequired = true;

        private double highEntropyThreshold = 4.2D;
    }

    @Data
    public static class ConversationWindow {

        private boolean enabled = true;

        /** 滑窗保留近 N 轮用户消息（仅内存，带 TTL，不落原文）。 */
        private int turns = 3;

        private long ttlSeconds = 1800L;

        /** 跨轮路径自身出错时是否阻断；为 null 时继承顶层 rag.guard.fail-closed。 */
        private Boolean failClosed;
    }

    @Data
    public static class Pii {

        private boolean enabled = false;

        private String type = "presidio";

        private String endpoint = "http://localhost:5002";

        private long timeoutMs = 300L;

        /** 远程 Presidio PII 扫描器开关（opt-in，需自托管 sidecar）。本地 PII 仍由 {@code enabled} 控制。 */
        private boolean providerEnabled = false;

        /**
         * Presidio 分析语言。支持取值 {@code "auto"}：按文本是否含 CJK 字符逐请求路由到 {@code zh}/{@code en}
         * （需 sidecar 已装中文 NER 模型）。默认仍为 {@code en}，保持既有部署行为不变。
         */
        private String language = "en";

        /** 低分实体过滤阈值 [0,1]，低于此分的 provider 命中丢弃（控误报率）。 */
        private double minScore = 0.5D;

        /**
         * provider 命中实体类型白名单：仅保留集合内类型，剔除 DATE_TIME 等贪婪/低风险类型（误报治理核心）。
         * 默认值为实测无误报、召回不受损的推荐白名单；置空列表则不过滤（来者不拒）。
         */
        private List<String> allowedTypes = List.of(
                "PERSON", "LOCATION", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE",
                "IP_ADDRESS", "US_SSN", "CRYPTO", "MEDICAL_LICENSE", "US_PASSPORT",
                "CN_USCC", "CN_LICENSE_PLATE", "CN_PASSPORT");

        /** 熔断：连续慢调用（≥ timeoutMs）达阈值后冷却窗内短路，避免 sidecar 挂起时每次吃满超时。 */
        private boolean circuitBreaker = true;

        private int circuitBreakerFailureThreshold = 3;

        private long circuitBreakerCooldownMs = 30000L;
    }

    @Data
    public static class PromptInjection {

        private boolean enabled = false;

        private String type = "llm-guard";

        private String endpoint = "http://localhost:8000";

        private long timeoutMs = 500L;

        /** 远程 LLM Guard 注入扫描器开关（opt-in，需自托管 sidecar）。本地 regex 仍由 enabled 控制。 */
        private boolean providerEnabled = false;

        /** provider 命中分数下限 [0,1]，低于丢弃（降误报）。 */
        private double minScore = 0.5D;

        /** 是否对 provider 调用启用三态熔断（连续失败后短路，冷却后半开探测）。 */
        private boolean circuitBreaker = true;

        /** 熔断触发的连续失败次数阈值。 */
        private int circuitBreakerFailureThreshold = 3;

        /** 熔断打开后的冷却时长（ms），冷却结束转半开。 */
        private long circuitBreakerCooldownMs = 30000L;
    }

    @Data
    public static class Audit {

        private boolean enabled = true;

        /** HMAC pepper 所在的环境变量名（指纹加盐密钥）。 */
        private String hmacPepperEnv = "GUARD_AUDIT_PEPPER";

        private int retainDays = 180;
    }
}
