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

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class CredentialScannerTest {

    private final GuardContext ctx = GuardContext.userInput("t", "tr", "c", "u");
    private final CredentialScanner scanner = new CredentialScanner();

    @Test
    void detectsAwsAccessKey() {
        // 合成 AKIA + 16 大写/数字（非真实凭据）。
        String text = "key=AKIAIOSFODNN7EXAMPLE";
        List<GuardFinding> findings = scanner.scan(text, ctx);
        assertThat(findings).anyMatch(f -> f.entityType() == GuardEntityType.API_KEY
                && f.ruleId().equals("aws-access-key")
                && text.substring(f.start(), f.end()).equals("AKIAIOSFODNN7EXAMPLE"));
    }

    @Test
    void detectsGithubPat() {
        String pat = "ghp_" + "a".repeat(36);
        List<GuardFinding> findings = scanner.scan("token " + pat, ctx);
        assertThat(findings).anyMatch(f -> f.ruleId().equals("github-pat"));
    }

    @Test
    void detectsOpenAiKeyViaAnchorNotBareSkPrefix() {
        // 带 T3BlbkFJ 锚点的合成串命中；裸 sk- 短串不命中（避免高误报）。
        String openai = "sk-" + "A".repeat(20) + "T3BlbkFJ" + "B".repeat(20);
        assertThat(scanner.scan(openai, ctx))
                .anyMatch(f -> f.ruleId().equals("openai-key"));
        assertThat(scanner.scan("sk-short", ctx)).isEmpty();
    }

    @Test
    void detectsJwt() {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummysignaturepart";
        List<GuardFinding> findings = scanner.scan("Authorization: Bearer " + jwt, ctx);
        assertThat(findings).anyMatch(f -> f.entityType() == GuardEntityType.JWT
                && text(jwt, findings).equals(jwt));
    }

    @Test
    void shortJwtLikeStringNotMatched() {
        // 段长不足（header/payload < 17、signature < 10）→ 不命中（收紧降误报）。
        assertThat(scanner.scan("eyJa.b.c", ctx)).noneMatch(f -> f.entityType() == GuardEntityType.JWT);
    }

    private static String text(String original, List<GuardFinding> findings) {
        GuardFinding jwt = findings.stream()
                .filter(f -> f.entityType() == GuardEntityType.JWT).findFirst().orElseThrow();
        return ("Authorization: Bearer " + original)
                .substring(jwt.start(), jwt.end());
    }

    @Test
    void detectsPasswordFieldValue() {
        String text = "password=Sup3rSecretValue!";
        List<GuardFinding> findings = scanner.scan(text, ctx);
        assertThat(findings).anyMatch(f -> f.entityType() == GuardEntityType.PASSWORD
                && text.substring(f.start(), f.end()).equals("Sup3rSecretValue!"));
    }

    @Test
    void genericApiKeyRequiresHighEntropyValue() {
        // 高熵随机值 → 命中；低熵重复值 → 不命中（兜底降误报）。
        String high = "api_key=" + "aZ9bX2cQ7dW4eR1tY6uK";
        assertThat(scanner.scan(high, ctx)).anyMatch(f -> f.ruleId().equals("generic-api-key"));
        String low = "api_key=aaaaaaaaaaaaaaaaaaaa";
        assertThat(scanner.scan(low, ctx)).noneMatch(f -> f.ruleId().equals("generic-api-key"));
    }

    @Test
    void cleanTextProducesNoFindings() {
        assertThat(scanner.scan("just a normal sentence without secrets", ctx)).isEmpty();
    }
}
