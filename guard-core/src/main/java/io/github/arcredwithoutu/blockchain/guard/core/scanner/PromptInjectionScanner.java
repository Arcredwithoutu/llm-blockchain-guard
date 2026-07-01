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
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import java.util.List;

/**
 * Prompt injection 扫描器——<b>本批占位</b>。
 *
 * <p>真实本地规则留批次三；当前 {@code supports} 由 config 控制（本批默认 false 即不参与），
 * {@code scan} 恒返回空，仅为保证 registry 完整。</p>
 */
public final class PromptInjectionScanner implements GuardScanner {

    private static final String NAME = "prompt-injection";

    private final boolean enabled;

    /** @param enabled 是否启用（本批占位，默认 false） */
    public PromptInjectionScanner(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean supports(GuardContext ctx) {
        return enabled;
    }

    @Override
    public List<GuardFinding> scan(String text, GuardContext ctx) {
        // 占位：本批不产出命中，本地规则待批次三补齐。
        return List.of();
    }
}
