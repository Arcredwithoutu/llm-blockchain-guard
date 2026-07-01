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

package io.github.arcredwithoutu.blockchain.guard.core.text;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class StructuredTextExtractorTest {

    @Test
    void extractsJsonStringFieldsWithSpan() {
        String json = "{\"phone\":\"13800000000\",\"mnemonic\":\"abandon about\"}";
        List<StructuredTextExtractor.Field> fields = StructuredTextExtractor.extract(json);
        assertThat(fields).anyMatch(f -> f.key().equals("mnemonic")
                && json.substring(f.valueStart(), f.valueEnd()).equals("abandon about"));
    }

    @Test
    void nonJsonFallsBackToWholeText() {
        List<StructuredTextExtractor.Field> fields = StructuredTextExtractor.extract("just text");
        assertThat(fields).hasSize(1);
        assertThat(fields.get(0).key()).isNull();
    }

    @Test
    void nestedObjectFieldsCarryDottedPath() {
        String json = "{\"wallet\":{\"privkey\":\"deadbeef\"}}";
        List<StructuredTextExtractor.Field> fields = StructuredTextExtractor.extract(json);
        assertThat(fields).anyMatch(f -> "wallet.privkey".equals(f.path())
                && json.substring(f.valueStart(), f.valueEnd()).equals("deadbeef"));
    }

    @Test
    void arrayStringElementsAreExtracted() {
        String json = "{\"keys\":[\"aaa\",\"bbb\"]}";
        List<StructuredTextExtractor.Field> fields = StructuredTextExtractor.extract(json);
        assertThat(fields).anyMatch(f -> json.substring(f.valueStart(), f.valueEnd()).equals("aaa"));
        assertThat(fields).anyMatch(f -> json.substring(f.valueStart(), f.valueEnd()).equals("bbb"));
    }

    @Test
    void escapedQuoteInValueDoesNotTruncateSpan() {
        // value 内含转义引号，span 须覆盖整个原文 value（含转义序列）。
        String json = "{\"note\":\"say \\\"hi\\\" now\"}";
        List<StructuredTextExtractor.Field> fields = StructuredTextExtractor.extract(json);
        assertThat(fields).anyMatch(f -> "note".equals(f.key())
                && json.substring(f.valueStart(), f.valueEnd()).equals("say \\\"hi\\\" now"));
    }

    @Test
    void malformedJsonFallsBackToWholeText() {
        String almost = "{\"phone\":\"13800000000\"";
        List<StructuredTextExtractor.Field> fields = StructuredTextExtractor.extract(almost);
        assertThat(fields).hasSize(1);
        assertThat(fields.get(0).key()).isNull();
        assertThat(fields.get(0).value()).isEqualTo(almost);
    }
}
