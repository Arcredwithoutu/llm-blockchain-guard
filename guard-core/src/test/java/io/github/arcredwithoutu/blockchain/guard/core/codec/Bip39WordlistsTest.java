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

package io.github.arcredwithoutu.blockchain.guard.core.codec;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class Bip39WordlistsTest {
    @Test
    void englishHas2048Words() {
        assertThat(Bip39Wordlists.english().size()).isEqualTo(2048);
        assertThat(Bip39Wordlists.indexOf("english", "abandon")).isEqualTo(0);
        assertThat(Bip39Wordlists.indexOf("english", "zoo")).isEqualTo(2047);
    }
    @Test
    void unknownWordReturnsMinusOne() {
        assertThat(Bip39Wordlists.indexOf("english", "notarealbip39word")).isEqualTo(-1);
    }
    @Test
    void chineseLoaded() {
        assertThat(Bip39Wordlists.wordlist("chinese_simplified").size()).isEqualTo(2048);
    }
}
