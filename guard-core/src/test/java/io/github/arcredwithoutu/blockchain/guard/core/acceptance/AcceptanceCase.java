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

package io.github.arcredwithoutu.blockchain.guard.core.acceptance;

import java.util.List;

/**
 * 验收用例 POJO（对应 guard-acceptance-test-spec §2 schema），由 Gson 反序列化 acceptance/*.json。
 *
 * <p>单条形态用 {@link #input}；多轮形态用 {@link #turns}+{@link #conversationId}（走 inspectTurn）。
 * 字段命名与 JSON key 一一对应，缺省字段反序列化为 null（由 Runner 兜底）。</p>
 */
public final class AcceptanceCase {

    String id;
    String category;
    String subCategory;
    String direction;
    String expectedAction;
    List<String> expectedEntityTypes;
    Integer expectedMinFindings;
    List<String> mustNotResidual;
    Boolean mayAllowFlowThrough;
    String expectedMaskFormat;
    String knownGap;
    String notes;
    String sampleSource;

    // 单条形态
    String input;

    // 多轮形态
    List<Turn> turns;
    String conversationId;
    Integer assertTurnIndex;

    /** 多轮单轮文本载体。 */
    static final class Turn {
        String text;
    }

    boolean isMultiTurn() {
        return turns != null && !turns.isEmpty();
    }

    boolean isDeferred() {
        return expectedAction != null && expectedAction.startsWith("deferred-");
    }

    boolean expectsEmpty() {
        return expectedEntityTypes == null || expectedEntityTypes.isEmpty();
    }

    int minFindings() {
        return expectedMinFindings == null ? 0 : expectedMinFindings;
    }
}
