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

package io.github.arcredwithoutu.blockchain.guard.core.mask;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FingerprintServiceTest {

    private final FingerprintService service = new FingerprintService("unit-test-pepper");

    @Test
    void fingerprint8IsEightHexChars() {
        String fp = service.fingerprint8("some-secret-value");
        assertThat(fp).hasSize(8).matches("[0-9a-f]{8}");
    }

    @Test
    void fingerprint16IsSixteenHexChars() {
        assertThat(service.fingerprint16("some-secret-value")).hasSize(16).matches("[0-9a-f]{16}");
    }

    @Test
    void deterministicForSameInput() {
        assertThat(service.fingerprint8("abc")).isEqualTo(service.fingerprint8("abc"));
    }

    @Test
    void differentPepperYieldsDifferentFingerprint() {
        FingerprintService other = new FingerprintService("another-pepper");
        assertThat(service.fingerprint8("abc")).isNotEqualTo(other.fingerprint8("abc"));
    }

    @Test
    void fingerprintDoesNotContainRawSecret() {
        // HMAC 不可逆，指纹不含原文片段。
        String secret = "deadbeefdeadbeef";
        assertThat(service.fingerprint16(secret)).doesNotContain(secret);
    }

    @Test
    void blankPepperRejected() {
        assertThatThrownBy(() -> new FingerprintService(" "))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
