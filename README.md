# Blockchain Guard

**Lightweight, deterministic privacy guard for blockchain RAG/Agent applications.**

Detects private keys, mnemonics, credentials, and PII across 8+ blockchains — pure POJO kernel with zero runtime dependency beyond BouncyCastle.

## Features

- **11 deterministic blockchain secret detection rules** covering EVM/SECP256k1, Bitcoin (WIF/xprv), BIP39 (English/Chinese), Solana, Sui, Substrate, Cardano, Stellar, Keystore JSON, PEM
- **PII scanning** — phone, email, ID card (mod11-2 checksum), bank card (Luhn), with ≤2% false positive rate
- **Credential detection** — API keys (OpenAI/AWS/GCP/GitHub), JWT, password fields
- **Address & tx-hash recognition** — identify without blocking (partial mask on persist)
- **Cross-turn conversation window guard** — detects secrets split across multiple messages
- **Structured text extraction** — JSON field-level scanning with context-aware field name normalization
- **HMAC-fingerprinted audit trail** — zero raw secret storage
- **Optional Presidio integration** — remote PII semantic enhancement with circuit breaker

## Modules

| Module | Description | Dependencies |
|--------|-------------|-------------|
| `guard-core` | Pure POJO kernel — detectors, scanners, policy engine, masker | BouncyCastle only |
| `guard-spring-boot-starter` | Spring Boot auto-configuration | guard-core + Spring Boot |

## Quick Start

```xml
<dependency>
  <groupId>io.github.arcredwithoutu.blockchain-guard</groupId>
  <artifactId>guard-spring-boot-starter</artifactId>
  <version>1.0.0</version>
</dependency>
```

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

GuardDecision decision = guardrailService.inspect(
    "my private key is 0x...",
    GuardContext.userInput("chat", "trace-id", "conv-id", "user-id")
);

if (decision.blocked()) {
    // secret detected — request blocked
}
```

Or **without Spring**:

```java
GuardrailService guard = GuardrailFixtures.defaultService("my-pepper");
GuardDecision d = guard.inspect(text, GuardContext.userInput("s", "t", "c", "u"));
```

## License

Apache 2.0
