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

package io.github.arcredwithoutu.blockchain.guard.core.audit;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 默认审计 Sink：用 {@code java.util.logging} 输出（core 不依赖 slf4j），<b>仅记 HMAC 指纹与脱敏元数据</b>。
 *
 * <p>绝不打印原文。任何 logging 异常都被吞掉，保证审计不影响主链路。</p>
 */
public final class LoggingGuardAuditSink implements GuardAuditSink {

    private static final Logger LOGGER = Logger.getLogger(LoggingGuardAuditSink.class.getName());

    @Override
    public void record(GuardEvent event) {
        if (event == null) {
            return;
        }
        try {
            LOGGER.log(Level.INFO, () -> format(event));
        } catch (RuntimeException ignored) {
            // 审计旁路：logging 失败绝不能冒泡影响主链路。
        }
    }

    /** 仅拼装脱敏字段（fingerprint/类型/动作等），不含任何原文片段。 */
    private static String format(GuardEvent e) {
        return "guard-event"
                + " direction=" + e.direction()
                + " source=" + e.source()
                + " entityType=" + e.entityType()
                + " riskLevel=" + e.riskLevel()
                + " action=" + e.action()
                + " ruleId=" + e.ruleId()
                + " fingerprint=" + e.fingerprint()
                + " spanCount=" + e.spanCount()
                + " elapsedMs=" + e.elapsedMs()
                + " traceId=" + e.traceId()
                + " conversationId=" + e.conversationId()
                + " userId=" + e.userId();
    }
}
