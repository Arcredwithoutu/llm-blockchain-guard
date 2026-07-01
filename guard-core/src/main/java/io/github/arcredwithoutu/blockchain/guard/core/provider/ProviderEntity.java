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

/**
 * 远程 provider 返回的实体命中（值对象，设计 §9.3 / R3）：与具体 provider 的字段名解耦，
 * 由各客户端把 Presidio `{entity_type,start,end,score}` / LLM Guard scanner 结果统一映射到此。
 *
 * <p>批次四由 {@code PiiScanner} 把 {@code score → confidence} 映射进 {@code GuardFinding}。
 * guard-core 内核不直接依赖此类做 secret 判定（secret 全走本地确定性规则）。</p>
 *
 * @param type  provider 给出的实体类型名（原样保留，如 "PERSON" / "EMAIL_ADDRESS" / scanner 名）
 * @param start 命中 span 起始下标（含）；provider 未给时为 -1
 * @param end   命中 span 结束下标（不含）；provider 未给时为 -1
 * @param score 风险/置信分 [0,1]
 */
public record ProviderEntity(String type, int start, int end, double score) {
}
