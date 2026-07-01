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

package io.github.arcredwithoutu.blockchain.guard.core.provider;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Presidio 客户端语言路由单测：仅验证 {@code resolveLanguage} 的逐请求语言判定，不发起真实 HTTP 请求。
 * 测试文本为合成文本，无任何真实 PII / 私钥。
 */
class PresidioGuardClientTest {

    @Test
    void fixedLanguageModeAlwaysUsesConfiguredLanguage() {
        // 非 auto 模式：无论中英文均返回固定语言（向后兼容，默认 en）。
        PresidioGuardClient en = new PresidioGuardClient("http://localhost:5002", "en", 300L);
        assertThat(en.resolveLanguage("张三的邮箱")).isEqualTo("en");
        assertThat(en.resolveLanguage("hello world")).isEqualTo("en");

        PresidioGuardClient zh = new PresidioGuardClient("http://localhost:5002", "zh", 300L);
        assertThat(zh.resolveLanguage("hello world")).isEqualTo("zh");
    }

    @Test
    void defaultConstructorUsesEnglish() {
        PresidioGuardClient client = new PresidioGuardClient("http://localhost:5002");
        assertThat(client.resolveLanguage("张三")).isEqualTo("en");
    }

    @Test
    void autoModeRoutesChineseToZhAndEnglishToEn() {
        PresidioGuardClient auto = new PresidioGuardClient("http://localhost:5002", "auto", 300L);
        assertThat(auto.resolveLanguage("张三住在北京市朝阳区")).isEqualTo("zh");
        assertThat(auto.resolveLanguage("Bob lives in New York")).isEqualTo("en");
        // 含 CJK 即判 zh（中英混排仍走 zh）。
        assertThat(auto.resolveLanguage("email 张三 alice@example.com")).isEqualTo("zh");
        // 纯数字/标点无 CJK → 兜底 en。
        assertThat(auto.resolveLanguage("2026-06-26 12:00")).isEqualTo("en");
    }

    @Test
    void autoModeIsCaseInsensitive() {
        PresidioGuardClient auto = new PresidioGuardClient("http://localhost:5002", "AUTO", 300L);
        assertThat(auto.resolveLanguage("北京")).isEqualTo("zh");
    }
}
