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

import static org.assertj.core.api.Assertions.assertThat;

import io.github.arcredwithoutu.blockchain.guard.core.api.GuardrailService;
import io.github.arcredwithoutu.blockchain.guard.core.scanner.ProviderInjectionScanner;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class GuardAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(GuardAutoConfiguration.class));

    @Test
    void registersGuardrailServiceWhenEnabled() {
        runner.withPropertyValues("rag.guard.enabled=true")
                .run(ctx -> assertThat(ctx).hasSingleBean(GuardrailService.class));
    }

    @Test
    void backsOffWhenDisabled() {
        runner.withPropertyValues("rag.guard.enabled=false")
                .run(ctx -> assertThat(ctx).doesNotHaveBean(GuardrailService.class));
    }

    @Test
    void providerInjectionScannerWiredWhenProviderEnabled() {
        runner.withPropertyValues("rag.guard.enabled=true",
                        "rag.guard.prompt-injection.provider-enabled=true",
                        "rag.guard.prompt-injection.endpoint=http://localhost:8000")
                .run(ctx -> assertThat(ctx).hasSingleBean(ProviderInjectionScanner.class));
    }

    @Test
    void providerInjectionScannerAbsentByDefault() {
        runner.withPropertyValues("rag.guard.enabled=true")
                .run(ctx -> assertThat(ctx).doesNotHaveBean(ProviderInjectionScanner.class));
    }
}
