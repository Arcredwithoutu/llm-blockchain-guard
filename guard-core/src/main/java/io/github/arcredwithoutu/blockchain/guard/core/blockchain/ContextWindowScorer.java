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

package io.github.arcredwithoutu.blockchain.guard.core.blockchain;

import java.util.List;
import java.util.Locale;

/** 在命中 span 前后窗口内匹配上下文词，用于提升/抑制风险判定。 */
public final class ContextWindowScorer {

    private final int window;

    public ContextWindowScorer(int window) {
        this.window = window;
    }

    /** 命中 span 前后 ±window 字符窗口内（小写）是否包含 terms 中任意词（小写）。 */
    public boolean hasAnyContext(String text, int start, int end, List<String> terms) {
        if (text == null || text.isEmpty() || terms == null || terms.isEmpty()) {
            return false;
        }
        int from = Math.max(0, start - window);
        int to = Math.min(text.length(), end + window);
        String haystack = text.substring(from, to).toLowerCase(Locale.ROOT);
        for (String term : terms) {
            if (term != null && !term.isEmpty() && haystack.contains(term.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }
}
