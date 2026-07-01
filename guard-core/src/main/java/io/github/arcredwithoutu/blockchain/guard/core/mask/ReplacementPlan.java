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

/**
 * 单个 span 的替换计划：把原文 {@code [start, end)} 替换为 {@code replacement}。
 *
 * @param start       原文起始下标（含）
 * @param end         原文结束下标（不含）
 * @param replacement 替换串（按实体类型由 §5.1 表生成）
 */
public record ReplacementPlan(int start, int end, String replacement) {
}
