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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Microsoft Presidio analyzer 客户端（设计 §9.3 / R3 坐实）：{@code POST {endpoint}/analyze}，
 * req {@code {text, language}} → resp {@code [{entity_type,start,end,score}]}，把 score 透传为 {@code ProviderEntity.score}。
 *
 * <p>JDK17 {@code java.net.http.HttpClient} 实现（零额外依赖）。<b>超时/异常/非 2xx 一律返回空列表、绝不抛出</b>——
 * provider 不可用时本地确定性 secret 判定不受影响（§9.3 红线）。调用前须由上游完成本地 secret scrub。</p>
 */
public final class PresidioGuardClient implements GuardProviderClient {

    private static final Logger LOGGER = Logger.getLogger(PresidioGuardClient.class.getName());
    private static final long DEFAULT_TIMEOUT_MILLIS = 300L;
    private static final String DEFAULT_LANGUAGE = "en";
    /** 自动语言路由标志：配置为 "auto" 时按文本是否含 CJK 字符逐请求选 zh/en。 */
    private static final String AUTO_LANGUAGE = "auto";
    private static final String LANGUAGE_ZH = "zh";

    private final String analyzeUrl;
    private final String language;
    /** 是否启用逐请求自动语言判定（config = "auto"）；为 false 时固定使用 {@link #language}。 */
    private final boolean autoLanguage;
    private final Duration timeout;
    private final HttpClient httpClient;

    public PresidioGuardClient(String endpoint) {
        this(endpoint, DEFAULT_LANGUAGE, DEFAULT_TIMEOUT_MILLIS);
    }

    public PresidioGuardClient(String endpoint, String language, long timeoutMillis) {
        Objects.requireNonNull(endpoint, "endpoint");
        this.analyzeUrl = stripTrailingSlash(endpoint) + "/analyze";
        this.autoLanguage = AUTO_LANGUAGE.equalsIgnoreCase(language);
        // auto 模式下 language 仅作非 CJK 文本的兜底；其余维持固定语言（默认 en，向后兼容）。
        this.language = language == null || language.isEmpty() ? DEFAULT_LANGUAGE
                : (this.autoLanguage ? DEFAULT_LANGUAGE : language);
        long millis = timeoutMillis <= 0 ? DEFAULT_TIMEOUT_MILLIS : timeoutMillis;
        this.timeout = Duration.ofMillis(millis);
        this.httpClient = HttpClient.newBuilder().connectTimeout(this.timeout).build();
    }

    @Override
    public List<ProviderEntity> analyze(String text) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        String requestLanguage = resolveLanguage(text);
        String requestBody = ProviderJson.objectOf("text", text, "language", requestLanguage);
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(analyzeUrl))
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                LOGGER.log(Level.FINE, "presidio analyze non-2xx status, degraded to empty");
                return List.of();
            }
            return ProviderJson.parseAnalyzeArray(response.body());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return List.of();
        } catch (Exception ex) {
            // 超时/连接拒绝/解析异常一律降级：本地 secret 判定不受影响（§9.3 红线）。
            LOGGER.log(Level.FINE, "presidio analyze failed, degraded to empty", ex);
            return List.of();
        }
    }

    /**
     * 解析本次请求使用的语言：auto 模式下含 CJK 字符走 zh、否则走 en（兜底语言）；非 auto 模式恒为固定 language。
     * 抽为包级方法便于单测。
     */
    String resolveLanguage(String text) {
        if (!autoLanguage) {
            return language;
        }
        return containsCjk(text) ? LANGUAGE_ZH : language;
    }

    /** 文本是否含 CJK 统一表意文字（U+4E00–U+9FFF），作为中文判定的轻量启发式。 */
    private static boolean containsCjk(String text) {
        if (text == null) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c >= 0x4E00 && c <= 0x9FFF) {
                return true;
            }
        }
        return false;
    }

    private static String stripTrailingSlash(String endpoint) {
        return endpoint.endsWith("/") ? endpoint.substring(0, endpoint.length() - 1) : endpoint;
    }
}
