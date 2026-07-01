# Blockchain Guard

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Java 17](https://img.shields.io/badge/java-17-orange)](https://adoptium.net/)
[![Maven Central](https://img.shields.io/badge/maven--central-1.0.0--SNAPSHOT-green)](#快速开始)

> **轻量级区块链隐私护栏 —— 确定性检测 8+ 链的私钥/助记词/凭据/PII，纯 POJO 内核，零 Spring 依赖，唯一外部库 BouncyCastle。**

**Blockchain Guard** 通过密码学校验（而非 LLM 猜测）识别 8+ 条区块链上的私钥、助记词、API 凭据和 PII。核心设计为**纯 POJO 内核**，可脱离 Spring 独立运行，同时提供 Spring Boot Starter 实现一行依赖接入。

[English Documentation](README.md)

---

## 架构

```mermaid
flowchart TD
    INPUT[用户输入 / 模型输出 / 工具调用 / 文档入库]
    INPUT --> PRE[localPreScrub 前置扫描<br/>11 条 DetectionRule 并行]
    PRE -->|命中 CRITICAL| BLOCK[BLOCK 阻断<br/>返回安全占位文本]
    PRE -->|无 CRITICAL| SCAN[ScannerRegistry.scanAll<br/>全量扫描器链]
    SCAN --> BS[BlockchainSecretScanner<br/>区块链密钥 · JSON 字段级]
    SCAN --> BA[BlockchainAddressScanner<br/>地址 / tx-hash 识别]
    SCAN --> CR[CredentialScanner<br/>API Key / JWT / Password]
    SCAN --> PI[PiiScanner<br/>手机 / 邮箱 / 身份证 / 银行卡]
    SCAN --> IJ[PromptInjectionScanner<br/>注入检测]
    SCAN --> PP[ProviderPiiScanner<br/>Presidio 远程增强 · opt-in]
    SCAN --> MERGE[SpanMerger.mergeWithinType<br/>同类型去重 · 跨类型保留]
    MERGE --> POLICY[PolicyEngine.decide<br/>11 方向 × 20+ 实体 决策矩阵]
    POLICY -->|BLOCK| BLOCK
    POLICY -->|MASK| MASKER[GuardMasker 掩码<br/>HMAC 指纹 · PII 子类标签 · 部分掩码]
    POLICY -->|ALLOW| PASS[原文放行]
    MASKER --> AUDIT[AuditSink.record 审计落库<br/>零原文存储]
    AUDIT --> PASS

    style PRE fill:#ff6b6b,color:#fff
    style BLOCK fill:#cc0000,color:#fff
    style POLICY fill:#ffd93d
    style MASKER fill:#6bcb77
    style AUDIT fill:#4d96ff,color:#fff
```

**处理管线**：正则粗筛 → 密码学解码校验 → 上下文窗口评分 → 策略决策（11 方向 × 20+ 实体类型）→ HMAC 指纹掩码 → 审计落库（绝不含原文）。

---

## 检测能力

### 区块链密钥（11 条确定性规则）

| # | 规则 | 实体类型 | 校验方法 | 特性 |
|---|------|----------|----------|------|
| 1 | BIP39 助记词 | `BLOCKCHAIN_MNEMONIC` | SHA256 checksum | 中英文词表；CJK 边界分词 |
| 2 | EVM 私钥 | `BLOCKCHAIN_PRIVATE_KEY_HEX` | secp256k1 曲线范围 (1 ≤ k ≤ n-1) | AIP-80 前缀；上下文感知（正向/负向/字段名） |
| 3 | Bitcoin WIF | `BLOCKCHAIN_PRIVATE_KEY_WIF` | Base58Check + 双 SHA256 | 主网/测试网 version byte |
| 4 | 扩展密钥 | `BLOCKCHAIN_EXTENDED_PRIVATE_KEY` | Base58Check + BIP32 序列化 | xprv/xpub/yprv/zprv/tprv (BIP32/SLIP-0132) |
| 5 | Solana 密钥对 | `BLOCKCHAIN_SOLANA_KEYPAIR` | Base58Check + 64 字节负载 | JSON 数组格式 `[215,29,...]` |
| 6 | Sui 私钥 | `BLOCKCHAIN_SUI_PRIVKEY` | Bech32 BCH + flag 校验 | SIP-15 `suiprivkey`；flag 0x00/0x01/0x02 |
| 7 | Substrate SURI | `BLOCKCHAIN_SUBSTRATE_SECRET_URI` | Base58Check | 派生路径检测（`//hard/soft///password`） |
| 8 | Cardano 签名密钥 | `BLOCKCHAIN_CARDANO_SIGNING_KEY` | CBOR hex + 结构校验 | `.skey` JSON 格式 |
| 9 | Stellar 种子 | `BLOCKCHAIN_STELLAR_SECRET_SEED` | Base32 + CRC16-XModem | `S...` StrKey 格式 |
| 10 | Keystore JSON | `BLOCKCHAIN_KEYSTORE_JSON` | JSON 结构校验（crypto.kdf, ciphertext） | 加密 keystore 同样 BLOCK |
| 11 | PEM 私钥 | `PEM_PRIVATE_KEY` | `-----BEGIN (EC/OPENSSH/RSA )?PRIVATE KEY-----` | 所有 PEM 变体 |

### 应用凭据

| 类型 | 实体 | 检测方法 | 置信度 |
|------|------|----------|--------|
| OpenAI API Key | `API_KEY` | `sk-*T3BlbkFJ*` 锚点（不用裸 `sk-` 前缀以降低误报） | 0.90 |
| AWS Access Key | `API_KEY` | `AKIA[0-9A-Z]{16}` | 0.95 |
| GCP API Key | `API_KEY` | `AIza[0-9A-Za-z_-]{35}` | 0.90 |
| GitHub PAT | `API_KEY` | `ghp_[0-9A-Za-z]{36}` | 0.95 |
| 通用 API Key | `API_KEY` | 字段名 + 高熵值（香农熵 ≥ 3.5 bits/char） | 0.60 |
| **JWT** | `JWT` | 三段式 base64url，header/payload 以 `ey` 起头 | 0.85 |
| 密码字段 | `PASSWORD` | 字段名模式（`password`/`passwd`/`pwd` + 值） | 0.90 |

### PII（误报率 ≤ 2%）

| 类型 | 实体 | 校验方法 | 置信度 |
|------|------|----------|--------|
| 中国手机号 | `PII` | `1[3-9]\d{9}` + 数字边界锚定 | 0.85 |
| 邮箱 | `PII` | RFC 风格正则，支持子域名和 plus addressing | 0.95 |
| 中国身份证 | `PII` | 18 位正则 + **mod11-2 校验位**（ISO 7064, GB11643） | 0.90 |
| 银行卡 | `PII` | 13-19 位正则 + **Luhn 算法** | 0.70 |

校验位错误（mod11-2 / Luhn 失败）→ **不命中**（误报控制护栏）。

### 地址与交易哈希（识别但不阻断）

| 类型 | 实体 | 检测方式 | 处置 |
|------|------|----------|------|
| EVM 地址 | `BLOCKCHAIN_ADDRESS` | `0x` + 40 hex，边界锚定 | 流转放行；落库部分掩码 |
| 比特币地址 | `BLOCKCHAIN_ADDRESS` | Base58/Bech32 候选 → `AddressClassifier` | 同上 |
| 交易哈希 | `BLOCKCHAIN_TX_HASH` | `0x` + 64 hex，负向上下文（`tx_hash`/`sha256`） | 放行（不误阻断） |

---

## 检测示例

### 1. 私钥 → 阻断

```java
String text = "我的私钥是 0x0000000000000000000000000000000000000000000000000000000000000001";
GuardDecision decision = guard.inspect(text,
    GuardContext.userInput("chat", "trace-001", "conv-001", "user-001"));

assert decision.blocked();
// sanitizedText: "[GUARD_BLOCKED: sensitive content removed]"
// userMessage: "检测到敏感信息（如私钥/助记词/凭据），出于安全已阻断本次请求..."
// finding: entityType=BLOCKCHAIN_PRIVATE_KEY_HEX, riskLevel=CRITICAL, action=BLOCK
```

### 2. PII → 掩码

```java
String text = "我的手机号是 13800000000，邮箱 test@example.com，请帮我查询账户。";
GuardDecision decision = guard.inspect(text,
    GuardContext.userInput("chat", "trace-002", "conv-002", "user-002"));

assert decision.action() == GuardAction.MASK;
// sanitizedText: "我的手机号是 [PII:PHONE]，邮箱 [PII:EMAIL]，请帮我查询账户。"
// 手机号和邮箱被替换为子类标签占位符 —— 原文绝不进入 LLM。
```

### 3. JWT → 阻断

```java
String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
GuardDecision decision = guard.inspect("Auth token: " + jwt,
    GuardContext.userInput("chat", "trace-003", "conv-003", "user-003"));

assert decision.blocked();
// JWT 命中 → 非持久化方向全 BLOCK。
// MEMORY_PERSIST 方向：MASK → [SECRET:JWT:<fp8>]
```

### 4. 密码字段 → 阻断

```java
String text = "database.password = mySecretPassword123";
GuardDecision decision = guard.inspect(text,
    GuardContext.userInput("chat", "trace-004", "conv-004", "user-004"));

assert decision.blocked();
// 字段名 "password" + 值 → BLOCK。
// 掩码格式: [SECRET:PASSWORD:<fp8>]
```

### 5. JSON 结构化检测

```java
String json = """
    {
      "wallet": {
        "private_key": "0x0000000000000000000000000000000000000000000000000000000000000001"
      }
    }""";
GuardDecision decision = guard.inspect(json,
    GuardContext.userInput("chat", "trace-005", "conv-005", "user-005"));

assert decision.blocked();
// StructuredTextExtractor: 字段级提取 + 上下文归一化
// "private_key" → 归一化为 "private key" → 正向上下文 → CRITICAL BLOCK
```

### 6. 跨轮分片检测

```java
ConversationWindowGuard windowGuard = /* 从 Spring 上下文或手工组装获取 */;

// 第 1 轮：助记词前半
windowGuard.inspectTurn("conv-006", "abandon abandon abandon abandon abandon abandon", ctx);
// → 未命中（不完整）

// 第 2 轮：后半
ConversationWindowGuard.Result result = windowGuard.inspectTurn("conv-006",
    "abandon abandon abandon abandon abandon about", ctx);
// → BLOCKED! 滑窗拼接成完整 12 词 → CRITICAL
```

---

## 快速开始

### Maven

```xml
<dependency>
  <groupId>io.github.arcredwithoutu.blockchain-guard</groupId>
  <artifactId>guard-spring-boot-starter</artifactId>
  <version>1.0.0</version>
</dependency>
```

### Spring Boot（使用 starter）

```yaml
rag:
  guard:
    enabled: true
    pii:
      enabled: true
```

```java
@Autowired
private GuardrailService guardrailService;

public void handleUserInput(String text) {
    GuardDecision decision = guardrailService.inspect(
        text, GuardContext.userInput("source", traceId, conversationId, userId));

    if (decision.blocked()) {
        throw new SecurityException(decision.userMessage());
    }
    // 安全放行 —— 使用 decision.sanitizedText() 获取掩码后内容
}
```

### 纯 Java（无 Spring）

```java
GuardrailService guard = GuardrailFixtures.defaultService("my-hmac-pepper");

GuardDecision decision = guard.inspect(
    "用户的输入内容...",
    GuardContext.userInput("my-app", "trace-id", "conv-id", "user-id")
);

switch (decision.action()) {
    case ALLOW -> { /* 无私钥/PII，直接放行 */ }
    case MASK  -> { /* PII 已被掩码 —— 用 decision.sanitizedText() */ }
    case BLOCK -> { /* CRITICAL 机密 —— 抛出 SecurityException */ }
}
```

### 接入 Presidio（可选，opt-in）

```yaml
rag:
  guard:
    pii:
      enabled: true
      provider-enabled: true          # 启用 Presidio sidecar
      endpoint: http://localhost:5002
      language: auto                  # 自动检测 CJK 文本路由到 zh 模型
      min-score: 0.5
      allowed-types: [PERSON, CREDIT_CARD, EMAIL_ADDRESS]
      circuit-breaker: true
```

Presidio 作为 PII 语义增强层，弥补本地正则无法覆盖的实体类型（人名、信用卡类型等）。外层包裹**三态熔断器**（关闭 → 打开 → 半开）——provider 故障时自动降级为空列表，绝不影响本地确定性判定。

---

## 配置参考

```yaml
rag:
  guard:
    enabled: true                         # 总开关
    fail-closed: true                     # 异常时阻断（fail-safe）
    max-scan-chars: 200000                # 单次最大扫描字符数

    local-secret:
      enabled: true
      bip39-languages: [english]          # 中文场景加 chinese_simplified
      check-bip39-checksum: true
      secp256k1-hex-context-required: true  # 裸 64hex 需正向上下文才检测

    conversation-window:
      enabled: true
      turns: 3                            # 滑窗轮数
      ttl-seconds: 1800                   # 缓冲过期时间

    pii:
      enabled: false                      # 本地 PII 规则
      provider-enabled: false             # Presidio sidecar（需自行部署）
      language: en                        # "auto" 自动 CJK 路由
      min-score: 0.5
      timeout-ms: 300

    prompt-injection:
      enabled: false
      provider-enabled: false             # LLM Guard sidecar（需自行部署）

    audit:
      enabled: true
      hmac-pepper-env: GUARD_AUDIT_PEPPER # HMAC 加盐环境变量
      retain-days: 180
```

---

## 测试覆盖

| 类别 | 数量 | 状态 |
|------|------|------|
| 单元测试 (JUnit 5 + AssertJ) | 276 | ✅ 全量通过 |
| 验收用例 (数据驱动 JSON) | 487 | ✅ PASS 376 / REGRESSION 69（全部为已知非缺陷项） |
| Spring Boot Starter 测试 | 4 | ✅ 全量通过 |
| GuardrailFixtures 无 Spring 装配验证 | 1 | ✅ 证明纯 POJO 构造可行性 |

```
验收观测基线：total=487 pass=376 regression=69
5 个关键验收缺口（G1–G5）全部通过 TDD 循环闭合。
```

---

## 项目结构

```
blockchain-guard/
├── guard-core/                          # 纯 POJO 内核
│   ├── api/          GuardScanner, GuardrailService, ScannerRegistry
│   ├── audit/        GuardAuditSink, GuardEvent（仅存指纹）
│   ├── blockchain/   11 条 DetectionRule + Detector + ContextScorer
│   ├── codec/        Base58Check, Bech32, Bip39Wordlists, Secp256k1Range
│   ├── engine/       DefaultGuardrailService（管线总入口）
│   ├── mask/         GuardMasker, FingerprintService, SpanMerger
│   ├── model/        GuardDecision, GuardFinding, GuardEntityType, ...
│   ├── policy/       GuardPolicyConfig（11×20 决策矩阵）, DirectionPolicy
│   ├── provider/     PresidioGuardClient, LlmGuardClient, CircuitBreaker
│   ├── scanner/      PiiScanner, BlockchainSecretScanner, CredentialScanner, ...
│   ├── session/      ConversationWindowGuard, InMemoryWindowStore
│   └── text/         StructuredTextExtractor（JSON 字段级提取）
└── guard-spring-boot-starter/           # Spring Boot 自动装配
    ├── GuardAutoConfiguration           # 纯手工 POJO 组装为 Spring Bean
    └── GuardProperties                  # YAML 配置绑定
```

---

## 设计原则

1. **确定性优于概率性** —— 私钥检测走密码学校验（checksum、曲线范围、编码格式），不用 LLM 分类器。有效私钥零漏检。

2. **默认 fail-closed** —— 内部异常触发 BLOCK 而非 ALLOW。provider 故障自动降级为纯本地扫描。

3. **零原文存储** —— 审计仅存 HMAC 指纹。掩码层用类型化标签替换原文（`[PII:PHONE]`、`[SECRET:JWT:<fp8>]`）。

4. **纯 POJO 内核** —— `guard-core` 零 Spring、零 Lombok、零 JSON 库。唯一运行时依赖：BouncyCastle（secp256k1 + SHA-256/HMAC）。

5. **TDD 驱动** —— 487 条 JSON Schema 驱动的验收用例框架。三色分桶报告（PASS/KNOWN-GAP/REGRESSION）。仅合成样本，源码中绝无真实密钥。

---

## License

Apache 2.0 — 详见 [LICENSE](LICENSE)。
