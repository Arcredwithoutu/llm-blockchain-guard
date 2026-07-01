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

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class ContextWindowScorerTest {
    @Test
    void positiveContextRaises() {
        ContextWindowScorer s = new ContextWindowScorer(48);
        String text = "my private key is " + "a".repeat(64);
        boolean hit = s.hasAnyContext(text, 18, 82, List.of("private key", "私钥"));
        assertThat(hit).isTrue();
    }

    @Test
    void negativeContextDetected() {
        ContextWindowScorer s = new ContextWindowScorer(48);
        String text = "tx_hash: " + "0".repeat(64);
        assertThat(s.hasAnyContext(text, 9, 73, List.of("tx_hash", "block_hash"))).isTrue();
    }
}
