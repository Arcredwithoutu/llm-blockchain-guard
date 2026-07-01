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

import java.util.HashMap;
import java.util.Map;

/** 计算字符串的 Shannon 熵（bits/char），用于高熵随机串兜底判据。 */
public final class EntropyScorer {

    private static final double LOG2 = Math.log(2);

    private EntropyScorer() {
    }

    /** 标准 Shannon 熵：-Σ p·log2(p)。空串返回 0。 */
    public static double shannon(String s) {
        if (s == null || s.isEmpty()) {
            return 0.0;
        }
        Map<Character, Integer> counts = new HashMap<>();
        for (int i = 0; i < s.length(); i++) {
            counts.merge(s.charAt(i), 1, Integer::sum);
        }
        double entropy = 0.0;
        double length = s.length();
        for (int count : counts.values()) {
            double p = count / length;
            entropy -= p * (Math.log(p) / LOG2);
        }
        return entropy;
    }
}
