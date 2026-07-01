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

package io.github.arcredwithoutu.blockchain.guard.core.blockchain;

import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import java.util.List;

/** 链上密钥检测规则 SPI：每条规则在文本中定位敏感 span 并给出风险判定。 */
public interface DetectionRule {

    /** 规则唯一标识，用于审计与去重。 */
    String ruleId();

    /** 在文本中检测命中，返回零个或多个 {@link RuleMatch}。 */
    List<RuleMatch> detect(String text, GuardContext ctx);
}
