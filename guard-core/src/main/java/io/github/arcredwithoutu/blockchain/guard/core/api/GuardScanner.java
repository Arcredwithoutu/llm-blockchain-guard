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

package io.github.arcredwithoutu.blockchain.guard.core.api;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import java.util.List;

/** 单类敏感实体扫描器 SPI（设计 §4.2）：在文本中定位命中并产出 {@link GuardFinding}。 */
public interface GuardScanner {

    /** 扫描器名称，用于审计/排序/诊断。 */
    String name();

    /** 当前上下文（方向/开关等）是否需要本扫描器参与。 */
    boolean supports(GuardContext ctx);

    /** 在文本中扫描命中。fingerprint 留空，统一在 mask 阶段补齐。 */
    List<GuardFinding> scan(String text, GuardContext ctx);
}
