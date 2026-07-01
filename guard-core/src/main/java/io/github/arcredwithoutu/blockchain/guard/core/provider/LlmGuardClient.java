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
 * Protect AI LLM Guard 客户端（设计 §9.3 / R3 坐实 {@code llm_guard_api/app/schemas.py}）：
 * {@code POST {endpoint}/analyze/prompt}，req {@code {prompt}} → resp {@code {is_valid,scanners,sanitized_prompt}}。
 *
 * <p>JDK17 {@code java.net.http.HttpClient}（零额外依赖）。<b>超时/异常/非 2xx → {@link LlmGuardResult#passthrough()}</b>
 * （valid=true，不误阻断）；{@link #analyze(String)} 把超阈值 scanner 映射成 {@link ProviderEntity}，
 * 失败同样返回空列表、绝不抛出。调用前须由上游完成本地 secret scrub（§9.3 红线）。</p>
 */
public final class LlmGuardClient implements GuardProviderClient {

    private static final Logger LOGGER = Logger.getLogger(LlmGuardClient.class.getName());
    private static final long DEFAULT_TIMEOUT_MILLIS = 300L;
    private static final double DEFAULT_SCORE_THRESHOLD = 0.5;

    private final String analyzePromptUrl;
    private final double scoreThreshold;
    private final Duration timeout;
    private final HttpClient httpClient;

    public LlmGuardClient(String endpoint) {
        this(endpoint, DEFAULT_SCORE_THRESHOLD, DEFAULT_TIMEOUT_MILLIS);
    }

    public LlmGuardClient(String endpoint, double scoreThreshold, long timeoutMillis) {
        Objects.requireNonNull(endpoint, "endpoint");
        this.analyzePromptUrl = stripTrailingSlash(endpoint) + "/analyze/prompt";
        this.scoreThreshold = scoreThreshold;
        long millis = timeoutMillis <= 0 ? DEFAULT_TIMEOUT_MILLIS : timeoutMillis;
        this.timeout = Duration.ofMillis(millis);
        this.httpClient = HttpClient.newBuilder().connectTimeout(this.timeout).build();
    }

    @Override
    public List<ProviderEntity> analyze(String text) {
        return analyzePrompt(text).toEntities(scoreThreshold);
    }

    /** 调 {@code /analyze/prompt}，返回完整结果；超时/异常/非 2xx → passthrough（valid=true，不误阻断）。 */
    public LlmGuardResult analyzePrompt(String text) {
        if (text == null || text.isEmpty()) {
            return LlmGuardResult.passthrough();
        }
        String requestBody = ProviderJson.objectOf("prompt", text);
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(analyzePromptUrl))
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                LOGGER.log(Level.FINE, "llm-guard analyze non-2xx status, degraded to passthrough");
                return LlmGuardResult.passthrough();
            }
            String body = response.body();
            return new LlmGuardResult(
                    ProviderJson.boolField(body, "is_valid", true),
                    ProviderJson.numberMapField(body, "scanners"),
                    ProviderJson.stringField(body, "sanitized_prompt"));
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return LlmGuardResult.passthrough();
        } catch (Exception ex) {
            // 超时/连接拒绝/解析异常一律降级：本地 secret 判定不受影响（§9.3 红线）。
            LOGGER.log(Level.FINE, "llm-guard analyze failed, degraded to passthrough", ex);
            return LlmGuardResult.passthrough();
        }
    }

    private static String stripTrailingSlash(String endpoint) {
        return endpoint.endsWith("/") ? endpoint.substring(0, endpoint.length() - 1) : endpoint;
    }
}
