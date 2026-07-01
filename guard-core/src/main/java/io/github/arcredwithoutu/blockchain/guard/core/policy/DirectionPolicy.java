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

package io.github.arcredwithoutu.blockchain.guard.core.policy;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardAction;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardDirection;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * 单一实体类别在各 {@link GuardDirection} 上的处置策略（设计 §7 表的一行）。
 *
 * <p>用 {@code per-direction override + defaultAction} 兜底，避免为 11 个方向逐格枚举；
 * 同一行内多数方向同动作，只把少数特例写进 override。</p>
 */
public final class DirectionPolicy {

    private final Map<GuardDirection, GuardAction> overrides;
    private final GuardAction defaultAction;

    public DirectionPolicy(Map<GuardDirection, GuardAction> overrides, GuardAction defaultAction) {
        this.defaultAction = Objects.requireNonNull(defaultAction, "defaultAction");
        // 不用 EnumMap 的 copy 构造器：空 map 会抛 "Specified map is empty"（无法推断 key 类型）。
        Map<GuardDirection, GuardAction> copy = new EnumMap<>(GuardDirection.class);
        if (overrides != null) {
            copy.putAll(overrides);
        }
        this.overrides = copy;
    }

    /** 全方向统一动作（无特例）。 */
    public static DirectionPolicy uniform(GuardAction action) {
        return new DirectionPolicy(Map.of(), action);
    }

    /** 取该方向动作，无 override 落 default。 */
    public GuardAction actionFor(GuardDirection direction) {
        return overrides.getOrDefault(direction, defaultAction);
    }
}
