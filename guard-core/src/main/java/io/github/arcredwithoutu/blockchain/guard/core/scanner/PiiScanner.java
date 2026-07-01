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

package io.github.arcredwithoutu.blockchain.guard.core.scanner;

import io.github.arcredwithoutu.blockchain.guard.core.api.GuardScanner;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardFinding;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PII 扫描器：本批仅本地正则（中英文手机/邮箱/身份证/银行卡）。
 *
 * <p>注意（R3）：Presidio 无开箱中文 NER，中文 PII 以本地规则为准、不依赖远程 provider；
 * Presidio provider 接入留批次四。{@code supports} 受 {@code pii.enabled} 控制，本批默认走本地规则。</p>
 */
public final class PiiScanner implements GuardScanner {

    private static final String NAME = "pii-local";
    // GB11643 身份证第 18 位 mod11-2 校验：前 17 位加权系数与校验码查表（ISO7064）。
    private static final int[] ID_CARD_WEIGHTS = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
    private static final char[] ID_CARD_CHECK_CODES = "10X98765432".toCharArray();

    // 中国大陆手机号：1[3-9] 起头 11 位，前后非数字边界。
    private static final Pattern CN_PHONE = Pattern.compile("(?<![0-9])1[3-9][0-9]{9}(?![0-9])");
    // 邮箱（通用）。
    private static final Pattern EMAIL = Pattern.compile(
            "[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}");
    // 中国大陆身份证：18 位，末位可为 X。
    private static final Pattern CN_ID_CARD = Pattern.compile(
            "(?<![0-9Xx])[1-9][0-9]{5}(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])"
                    + "[0-9]{3}[0-9Xx](?![0-9Xx])");
    // 银行卡号：13–19 位连续数字（前后非数字边界）。
    private static final Pattern BANK_CARD = Pattern.compile("(?<![0-9])[0-9]{13,19}(?![0-9])");

    private final boolean localEnabled;

    /** @param localEnabled 是否启用本地 PII 规则（对应 {@code pii.enabled}，本批默认 true） */
    public PiiScanner(boolean localEnabled) {
        this.localEnabled = localEnabled;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean supports(GuardContext ctx) {
        return localEnabled;
    }

    @Override
    public List<GuardFinding> scan(String text, GuardContext ctx) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        List<GuardFinding> findings = new ArrayList<>();
        // 身份证、银行卡在前——避免被手机号/数字串规则抢占（数字越界由各自边界保证）。
        matchIdCard(findings, text);
        match(findings, text, EMAIL, "pii-email", 0.95);
        match(findings, text, CN_PHONE, "pii-cn-phone", 0.85);
        matchBankCard(findings, text);
        return findings;
    }

    private static void match(List<GuardFinding> findings, String text, Pattern pattern,
            String ruleId, double confidence) {
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            findings.add(new GuardFinding(GuardEntityType.PII, GuardRiskLevel.MEDIUM, confidence,
                    m.start(), m.end(), ruleId, "matched " + ruleId, null));
        }
    }

    /** 身份证：18 位正则粗筛后做 mod11-2 校验位验证，校验不符不命中（GB11643，降误报 ≤2%）。 */
    private static void matchIdCard(List<GuardFinding> findings, String text) {
        Matcher m = CN_ID_CARD.matcher(text);
        while (m.find()) {
            if (isValidIdCardChecksum(m.group())) {
                findings.add(new GuardFinding(GuardEntityType.PII, GuardRiskLevel.MEDIUM, 0.9,
                        m.start(), m.end(), "pii-cn-id-card", "matched pii-cn-id-card", null));
            }
        }
    }

    /** ISO7064 mod11-2：前 17 位加权和 mod 11 查表，与第 18 位（X 不区分大小写）比对。 */
    private static boolean isValidIdCardChecksum(String idCard) {
        int sum = 0;
        for (int i = 0; i < 17; i++) {
            sum += (idCard.charAt(i) - '0') * ID_CARD_WEIGHTS[i];
        }
        char expected = ID_CARD_CHECK_CODES[sum % 11];
        return Character.toUpperCase(idCard.charAt(17)) == expected;
    }

    /** 银行卡号：与身份证(18)/手机号(11) 长度区间不重叠；命中后再做 Luhn 校验以降低普通长数字误报。 */
    private static void matchBankCard(List<GuardFinding> findings, String text) {
        Matcher m = BANK_CARD.matcher(text);
        while (m.find()) {
            int len = m.end() - m.start();
            // 11 位被手机号规则覆盖；这里只收 13–19 且非已被身份证规则吃掉的串。
            if (overlaps(findings, m.start(), m.end()) || !isValidLuhn(m.group())) {
                continue;
            }
            findings.add(new GuardFinding(GuardEntityType.PII, GuardRiskLevel.MEDIUM, 0.7,
                    m.start(), m.end(), "pii-bank-card", "matched bank card (" + len + " digits)", null));
        }
    }

    /** 银行卡 Luhn 校验：从右向左隔位加倍，超过 9 则减 9，最终和可被 10 整除。 */
    private static boolean isValidLuhn(String digits) {
        int sum = 0;
        boolean doubleDigit = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int n = digits.charAt(i) - '0';
            if (doubleDigit) {
                n *= 2;
                if (n > 9) {
                    n -= 9;
                }
            }
            sum += n;
            doubleDigit = !doubleDigit;
        }
        return sum % 10 == 0;
    }

    private static boolean overlaps(List<GuardFinding> findings, int start, int end) {
        for (GuardFinding f : findings) {
            if (start < f.end() && f.start() < end) {
                return true;
            }
        }
        return false;
    }
}
