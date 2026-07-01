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
import io.github.arcredwithoutu.blockchain.guard.core.api.ScannerRegistry;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** 默认扫描器注册表：持有有序扫描器列表，按注册顺序聚合 supports 当前上下文的命中。 */
public final class DefaultScannerRegistry implements ScannerRegistry {

    private final List<GuardScanner> scanners;

    /** @param scanners 有序扫描器列表（约定 Blockchain → Credential → Pii → PromptInjection） */
    public DefaultScannerRegistry(List<GuardScanner> scanners) {
        this.scanners = List.copyOf(Objects.requireNonNull(scanners, "scanners"));
    }

    @Override
    public List<GuardFinding> scanAll(String text, GuardContext ctx) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        List<GuardFinding> findings = new ArrayList<>();
        for (GuardScanner scanner : scanners) {
            if (scanner.supports(ctx)) {
                findings.addAll(scanner.scan(text, ctx));
            }
        }
        return findings;
    }
}
