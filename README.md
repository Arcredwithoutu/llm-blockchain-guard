# Blockchain Guard

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Java 17](https://img.shields.io/badge/java-17-orange)](https://adoptium.net/)
[![Maven Central](https://img.shields.io/badge/maven--central-1.0.0--SNAPSHOT-green)](#quick-start)

> **Lightweight, deterministic privacy guard for blockchain RAG and Agent applications — zero Spring dependency, one external library (BouncyCastle).**

**Blockchain Guard** detects private keys, mnemonics, API credentials, and PII across 8+ blockchains using cryptographic validation (not LLM guessing). It is designed as a **pure POJO kernel** that can run without Spring, with an optional Spring Boot starter for drop-in integration.

[中文文档](README_CN.md)

---

## Architecture

```mermaid
flowchart TD
    INPUT[User Input / Model Output / Tool I/O / Document Ingestion]
    INPUT --> PRE[localPreScrub<br/>11 DetectionRules]
    PRE -->|CRITICAL hit| BLOCK[BLOCK<br/>safe placeholder returned]
    PRE -->|no CRITICAL| SCAN[ScannerRegistry.scanAll]
    SCAN --> BS[BlockchainSecretScanner<br/>JSON field-level]
    SCAN --> BA[BlockchainAddressScanner<br/>address / tx-hash]
    SCAN --> CR[CredentialScanner<br/>API Key / JWT / Password]
    SCAN --> PI[PiiScanner<br/>Phone / Email / ID / BankCard]
    SCAN --> IJ[PromptInjectionScanner]
    SCAN --> PP[ProviderPiiScanner<br/>Presidio sidecar ▪ opt-in]
    SCAN --> MERGE[SpanMerger.mergeWithinType<br/>same-type dedup ▪ cross-type preserve]
    MERGE --> POLICY[PolicyEngine.decide<br/>11 directions × 20+ entity types]
    POLICY -->|BLOCK| BLOCK
    POLICY -->|MASK| MASKER[GuardMasker<br/>HMAC fingerprint ▪ PII subtype ▪ partial mask]
    POLICY -->|ALLOW| PASS[Pass through]
    MASKER --> AUDIT[AuditSink.record<br/>zero raw secret storage]
    AUDIT --> PASS

    style PRE fill:#ff6b6b,color:#fff
    style BLOCK fill:#cc0000,color:#fff
    style POLICY fill:#ffd93d
    style MASKER fill:#6bcb77
    style AUDIT fill:#4d96ff,color:#fff
```

**Pipeline**: RegEx coarse match → Cryptographic decode & validation → Context-window scoring → Policy decision (11 directions × 20+ entity types) → HMAC-fingerprinted masking → Audit (zero raw secret storage).

---

## Detection Capabilities

### Blockchain Secrets (11 deterministic rules)

| # | Rule | Entity Type | Validation | Key Features |
|---|------|-------------|------------|--------------|
| 1 | BIP39 Mnemonic | `BLOCKCHAIN_MNEMONIC` | SHA256 checksum | English/Chinese wordlists; CJK boundary segmentation |
| 2 | EVM Private Key | `BLOCKCHAIN_PRIVATE_KEY_HEX` | secp256k1 curve range (1 ≤ k ≤ n-1) | AIP-80 prefix; context-aware (positive/negative/field-name) |
| 3 | Bitcoin WIF | `BLOCKCHAIN_PRIVATE_KEY_WIF` | Base58Check + double-SHA256 | Mainnet/Testnet version bytes |
| 4 | Extended Keys | `BLOCKCHAIN_EXTENDED_PRIVATE_KEY` | Base58Check + BIP32 serialization | xprv/xpub/yprv/zprv/tprv (BIP32/SLIP-0132) |
| 5 | Solana Keypair | `BLOCKCHAIN_SOLANA_KEYPAIR` | Base58Check + 64-byte payload | JSON array form `[215,29,...]` support |
| 6 | Sui Private Key | `BLOCKCHAIN_SUI_PRIVKEY` | Bech32 BCH + flag validation | SIP-15 `suiprivkey`; flags 0x00/0x01/0x02 |
| 7 | Substrate SURI | `BLOCKCHAIN_SUBSTRATE_SECRET_URI` | Base58Check | Derivation path (`//hard/soft///password`) detection |
| 8 | Cardano Signing Key | `BLOCKCHAIN_CARDANO_SIGNING_KEY` | CBOR hex + structure validation | `.skey` JSON format |
| 9 | Stellar Seed | `BLOCKCHAIN_STELLAR_SECRET_SEED` | Base32 + CRC16-XModem | `S...` StrKey format |
| 10 | Keystore JSON | `BLOCKCHAIN_KEYSTORE_JSON` | JSON structure (crypto.kdf, ciphertext) | EVM encrypted keystores (even encrypted → BLOCK) |
| 11 | PEM Private Key | `PEM_PRIVATE_KEY` | `-----BEGIN (EC/OPENSSH/RSA )?PRIVATE KEY-----` | All PEM variants |

### Credentials

| Type | Entity | Detection Method | Confidence |
|------|--------|-----------------|------------|
| OpenAI API Key | `API_KEY` | `sk-*T3BlbkFJ*` anchor (no bare `sk-` to avoid false positives) | 0.90 |
| AWS Access Key | `API_KEY` | `AKIA[0-9A-Z]{16}` | 0.95 |
| GCP API Key | `API_KEY` | `AIza[0-9A-Za-z_-]{35}` | 0.90 |
| GitHub PAT | `API_KEY` | `ghp_[0-9A-Za-z]{36}` | 0.95 |
| Generic API Key | `API_KEY` | Field-name + high-entropy value (Shannon entropy ≥ 3.5 bits/char) | 0.60 |
| **JWT** | `JWT` | Three-segment base64url with `ey` header/payload prefix | 0.85 |
| Password Field | `PASSWORD` | Field-name patterns (`password`/`passwd`/`pwd` + value) | 0.90 |

### PII (false positive rate ≤ 2%)

| Type | Entity | Validation | Confidence |
|------|--------|-----------|------------|
| Chinese Phone | `PII` | `1[3-9]\d{9}` with numeric boundaries | 0.85 |
| Email | `PII` | RFC-like regex with subdomain/plus-addressing | 0.95 |
| Chinese ID Card | `PII` | 18-digit regex + **mod11-2 checksum** (ISO 7064, GB11643) | 0.90 |
| Bank Card | `PII` | 13-19 digit regex + **Luhn algorithm** | 0.70 |

Invalid checksums (mod11-2 or Luhn) → **no hit** (false positive control).

### Address & Transaction Hash (identify, don't block)

| Type | Entity | Detection | Behavior |
|------|--------|-----------|----------|
| EVM Address | `BLOCKCHAIN_ADDRESS` | `0x` + 40 hex, boundary-anchored | ALLOW on input; partial mask on persist |
| Bitcoin Address | `BLOCKCHAIN_ADDRESS` | Base58/Bech32 candidates → `AddressClassifier` | Same as above |
| Transaction Hash | `BLOCKCHAIN_TX_HASH` | `0x` + 64 hex, negative context (`tx_hash`/`sha256`) | ALLOW (not blocked) |

---

## Detection Examples

### 1. Private Key → BLOCK

```java
String text = "我的私钥是 0x0000000000000000000000000000000000000000000000000000000000000001";
GuardDecision decision = guard.inspect(text,
    GuardContext.userInput("chat", "trace-001", "conv-001", "user-001"));

assert decision.blocked();
// sanitizedText: "[GUARD_BLOCKED: sensitive content removed]"
// userMessage: "检测到敏感信息（如私钥/助记词/凭据），出于安全已阻断本次请求..."
// finding: entityType=BLOCKCHAIN_PRIVATE_KEY_HEX, riskLevel=CRITICAL, action=BLOCK
```

### 2. PII → MASK

```java
String text = "我的手机号是 13800000000，邮箱 test@example.com，请帮我查询账户。";
GuardDecision decision = guard.inspect(text,
    GuardContext.userInput("chat", "trace-002", "conv-002", "user-002"));

assert decision.action() == GuardAction.MASK;
// sanitizedText: "我的手机号是 [PII:PHONE]，邮箱 [PII:EMAIL]，请帮我查询账户。"
// Phone and email replaced with typed placeholders — no raw data reaches the LLM.
```

### 3. JWT → BLOCK

```java
String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
GuardDecision decision = guard.inspect("Auth token: " + jwt,
    GuardContext.userInput("chat", "trace-003", "conv-003", "user-003"));

assert decision.blocked();
// JWT detected → BLOCK on all non-persist directions.
// On MEMORY_PERSIST: MASK → [SECRET:JWT:<fp8>]
```

### 4. Password Field → BLOCK

```java
String text = "database.password = mySecretPassword123";
GuardDecision decision = guard.inspect(text,
    GuardContext.userInput("chat", "trace-004", "conv-004", "user-004"));

assert decision.blocked();
// Field name "password" + value → BLOCK.
// Mask format: [SECRET:PASSWORD:<fp8>]
```

### 5. JSON Structured Detection

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
// StructuredTextExtractor: field-level extraction + context-aware normalization
// "private_key" → normalized to "private key" → positive context → CRITICAL BLOCK
```

### 6. Cross-Turn Detection

```java
ConversationWindowGuard windowGuard = /* from Spring context or manual assembly */;

// Turn 1: first half of mnemonic
windowGuard.inspectTurn("conv-006", "abandon abandon abandon abandon abandon abandon", ctx);
// → no hit (incomplete)

// Turn 2: second half
ConversationWindowGuard.Result result = windowGuard.inspectTurn("conv-006",
    "abandon abandon abandon abandon abandon about", ctx);
// → BLOCKED! Sliding window reassembled 12 words → CRITICAL.
```

---

## Quick Start

### Maven

```xml
<dependency>
  <groupId>io.github.arcredwithoutu.blockchain-guard</groupId>
  <artifactId>guard-spring-boot-starter</artifactId>
  <version>1.0.0</version>
</dependency>
```

### Spring Boot (with starter)

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
    // Safe to proceed — use decision.sanitizedText() for masked content
}
```

### Pure Java (without Spring)

```java
GuardrailService guard = GuardrailFixtures.defaultService("my-hmac-pepper");

GuardDecision decision = guard.inspect(
    "user text with potential secrets...",
    GuardContext.userInput("my-app", "trace-id", "conv-id", "user-id")
);

if (decision.action() == GuardAction.ALLOW) {
    // No secrets detected
} else if (decision.action() == GuardAction.MASK) {
    // PII detected and masked — use decision.sanitizedText()
    String safeText = decision.sanitizedText();
} else {
    // CRITICAL secret or credential → BLOCK
    throw new SecurityException(decision.userMessage());
}
```

### Presidio Integration (optional, opt-in)

```yaml
rag:
  guard:
    pii:
      enabled: true
      provider-enabled: true          # opt-in Presidio sidecar
      endpoint: http://localhost:5002
      language: auto                  # auto-routes CJK text to zh model
      min-score: 0.5
      allowed-types: [PERSON, CREDIT_CARD, EMAIL_ADDRESS]
      circuit-breaker: true
```

Presidio enriches PII detection with semantic entity types (PERSON, CREDIT_CARD, etc.) that local regex rules cannot cover. Wrapped in a **three-state circuit breaker** (closed → open → half-open) — provider failure never affects local deterministic scanning.

---

## Configuration Reference

```yaml
rag:
  guard:
    enabled: true                         # Master switch
    fail-closed: true                     # Fail-safe: block on internal errors
    max-scan-chars: 200000

    local-secret:
      enabled: true
      bip39-languages: [english]          # [english, chinese_simplified] for CJK
      check-bip39-checksum: true
      secp256k1-hex-context-required: true  # Requires positive context for 64-hex

    conversation-window:
      enabled: true
      turns: 3                            # Sliding window size
      ttl-seconds: 1800                   # Buffer expiry

    pii:
      enabled: false                      # Local PII rules
      provider-enabled: false             # Presidio sidecar (requires deployment)
      language: en                        # "auto" for CJK-aware routing
      min-score: 0.5
      timeout-ms: 300

    prompt-injection:
      enabled: false
      provider-enabled: false             # LLM Guard sidecar (requires deployment)
      min-score: 0.5

    audit:
      enabled: true
      hmac-pepper-env: GUARD_AUDIT_PEPPER
      retain-days: 180
```

---

## Test Coverage

| Category | Count | Status |
|----------|-------|--------|
| Unit tests (JUnit 5 + AssertJ) | 276 | ✅ All passing |
| Acceptance cases (data-driven JSON) | 487 | ✅ 376 PASS / 69 regression (known non-defects) |
| Spring Boot starter tests | 4 | ✅ All passing |
| GuardrailFixtures (zero-Spring assembly) | 1 | ✅ Proves pure POJO construction |

```
Acceptance observation: total=487 pass=376 regression=69
All 5 critical findings (G1–G5) resolved through TDD cycle.
```

---

## Project Structure

```
blockchain-guard/
├── guard-core/                          # Pure POJO kernel
│   ├── api/          GuardScanner, GuardrailService, ScannerRegistry
│   ├── audit/        GuardAuditSink, GuardEvent (HMAC-only)
│   ├── blockchain/   11 DetectionRules + Detector + ContextScorer
│   ├── codec/        Base58Check, Bech32, Bip39Wordlists, Secp256k1Range
│   ├── engine/       DefaultGuardrailService (pipeline orchestrator)
│   ├── mask/         GuardMasker, FingerprintService, SpanMerger
│   ├── model/        GuardDecision, GuardFinding, GuardEntityType, ...
│   ├── policy/       GuardPolicyConfig (11×20 matrix), DirectionPolicy
│   ├── provider/     PresidioGuardClient, LlmGuardClient, CircuitBreaker
│   ├── scanner/      PiiScanner, BlockchainSecretScanner, CredentialScanner, ...
│   ├── session/      ConversationWindowGuard, InMemoryWindowStore
│   └── text/         StructuredTextExtractor (JSON field-level)
└── guard-spring-boot-starter/           # Spring Boot auto-configuration
    ├── GuardAutoConfiguration           # Manual POJO assembly as Spring beans
    └── GuardProperties                  # YAML config binding
```

---

## Design Principles

1. **Deterministic over probabilistic** — Private key detection uses cryptographic validation (checksums, curve ranges, encoding), not LLM classifiers. No false negatives on valid private keys.

2. **Fail-closed by default** — Internal errors trigger BLOCK (not ALLOW). Provider outages degrade gracefully to local-only scanning.

3. **Zero raw secret storage** — Audit trail stores only HMAC fingerprints. Masker replaces secrets with typed labels (`[PII:PHONE]`, `[SECRET:JWT:<fp8>]`).

4. **Pure POJO kernel** — `guard-core` has zero Spring, zero Lombok, zero JSON libraries. One runtime dependency: BouncyCastle for secp256k1 and SHA-256/HMAC.

5. **Test-driven from day one** — 487 acceptance cases in a JSON-schema-defined framework. Three-color reporting (PASS/KNOWN-GAP/REGRESSION). Synthetic test samples only (no real secrets in code).

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
