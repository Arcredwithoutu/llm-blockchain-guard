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

import io.github.arcredwithoutu.blockchain.guard.core.codec.Bip39Wordlists;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardContext;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardEntityType;
import io.github.arcredwithoutu.blockchain.guard.core.model.GuardRiskLevel;
import org.bouncycastle.crypto.digests.SHA256Digest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * BIP39 助记词检测规则：按词边界滑窗定位 wordlist 词的连续 run，对合法词数子窗做 checksum 校验。
 * checksum 通过 → CRITICAL/0.99；失败但命中助记词上下文 → HIGH（REVIEW 兜底）。
 */
public final class Bip39MnemonicRule implements DetectionRule {

    private static final String RULE_ID = "bip39-mnemonic";
    private static final Set<Integer> VALID_WORD_COUNTS = Set.of(12, 15, 18, 21, 24);
    private static final int BITS_PER_WORD = 11;
    // 无空格连写的 CJK 助记词需逐字成 token；chinese_simplified 词表为单字。
    private static final String CJK_LANGUAGE = "chinese_simplified";
    private static final List<String> MNEMONIC_CONTEXT =
            List.of("mnemonic", "seed phrase", "recovery phrase", "助记词", "恢复词", "种子短语");
    private static final ContextWindowScorer CONTEXT_SCORER = new ContextWindowScorer(48);

    private final List<String> languages;
    private final boolean checkChecksum;

    public Bip39MnemonicRule(List<String> languages, boolean checkChecksum) {
        this.languages = List.copyOf(Objects.requireNonNull(languages, "languages"));
        this.checkChecksum = checkChecksum;
    }

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<RuleMatch> detect(String text, GuardContext ctx) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        // 多语言结果可能在同一 span 上重复命中，去重交由下游 SpanMerger 统一处理。
        List<RuleMatch> matches = new ArrayList<>();
        for (String language : languages) {
            matches.addAll(detectForLanguage(text, language));
        }
        return matches;
    }

    private List<RuleMatch> detectForLanguage(String text, String language) {
        List<int[]> spans = tokenSpans(text, language);
        List<int[]> runs = wordlistRuns(text, spans, language);
        List<RuleMatch> matches = new ArrayList<>();
        for (int[] run : runs) {
            matches.addAll(scanRun(text, spans, run[0], run[1], language));
        }
        return matches;
    }

    /** 在一段连续 wordlist 词 run 内尝试所有合法词数子窗（短窗失败不放弃长窗）。 */
    private List<RuleMatch> scanRun(String text, List<int[]> spans, int runStart, int runEnd, String language) {
        List<RuleMatch> matches = new ArrayList<>();
        for (int count : VALID_WORD_COUNTS) {
            for (int i = runStart; i + count <= runEnd; i++) {
                int start = spans.get(i)[0];
                int end = spans.get(i + count - 1)[1];
                RuleMatch match = evaluateWindow(text, spans, i, count, language, start, end);
                if (match != null) {
                    matches.add(match);
                }
            }
        }
        return matches;
    }

    private RuleMatch evaluateWindow(String text, List<int[]> spans, int from, int count,
            String language, int start, int end) {
        int[] indices = new int[count];
        for (int k = 0; k < count; k++) {
            int[] span = spans.get(from + k);
            indices[k] = lookup(language, text, span);
        }
        boolean checksumOk = checkChecksum && verifyChecksum(indices, count);
        if (checksumOk) {
            return new RuleMatch(GuardEntityType.BLOCKCHAIN_MNEMONIC, GuardRiskLevel.CRITICAL,
                    0.99, start, end, RULE_ID, "BIP39 checksum valid (" + count + " words)");
        }
        if (CONTEXT_SCORER.hasAnyContext(text, start, end, MNEMONIC_CONTEXT)) {
            return new RuleMatch(GuardEntityType.BLOCKCHAIN_MNEMONIC, GuardRiskLevel.HIGH,
                    0.6, start, end, RULE_ID, "mnemonic-shaped words with context, checksum unverified");
        }
        return null;
    }

    /** 拼 ENT+CS bit，重算 SHA256(entropy) 前 CS bit 与尾部 checksum bit 比对。 */
    private boolean verifyChecksum(int[] indices, int count) {
        int totalBits = count * BITS_PER_WORD;
        int checksumBits = totalBits / 32;
        int entropyBits = totalBits - checksumBits;
        byte[] bits = new byte[totalBits];
        for (int w = 0; w < count; w++) {
            int index = indices[w];
            for (int b = 0; b < BITS_PER_WORD; b++) {
                bits[w * BITS_PER_WORD + b] = (byte) ((index >> (BITS_PER_WORD - 1 - b)) & 1);
            }
        }
        byte[] entropy = new byte[entropyBits / 8];
        for (int i = 0; i < entropyBits; i++) {
            if (bits[i] == 1) {
                entropy[i / 8] |= (byte) (1 << (7 - (i % 8)));
            }
        }
        byte[] hash = sha256(entropy);
        for (int i = 0; i < checksumBits; i++) {
            int hashBit = (hash[i / 8] >> (7 - (i % 8))) & 1;
            if (hashBit != bits[entropyBits + i]) {
                return false;
            }
        }
        return true;
    }

    private static byte[] sha256(byte[] data) {
        SHA256Digest digest = new SHA256Digest();
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    /** 查 wordlist 索引：查表前 lowercase（英文大小写无关，CJK 不受影响），span 偏移指向原文不变。 */
    private static int lookup(String language, String text, int[] span) {
        String token = text.substring(span[0], span[1]).toLowerCase(Locale.ROOT);
        return Bip39Wordlists.indexOf(language, token);
    }

    /**
     * 按语言分词：CJK 助记词常无空格连写，对 {@value #CJK_LANGUAGE} 逐字成 token
     * （每个 CJK 单字一个 span，非 CJK 字符跳过）；其余语言按空白边界分词。
     */
    private static List<int[]> tokenSpans(String text, String language) {
        if (CJK_LANGUAGE.equals(language)) {
            return cjkCharSpans(text);
        }
        return latinTokenSpans(text);
    }

    /**
     * 非 CJK 语言分词：以空白「及」CJK/全角标点为词边界切分（验收 G2）。仅按空白（{@code \S+}）时，
     * 中文前缀无空格紧贴英文助记词（如「助记词（mnemonic）：abandon…」）会把「前缀+首词」黏成一个
     * 非 wordlist token，使连续词数少 1 而漏检；故对 CJK 汉字与 CJK/全角标点也视为词边界。纯 ASCII
     * 文本下与 {@code \S+} 等价（不改变既有英文助记词检出）。
     */
    private static List<int[]> latinTokenSpans(String text) {
        List<int[]> spans = new ArrayList<>();
        int runStart = -1;
        int i = 0;
        while (i < text.length()) {
            int codePoint = text.codePointAt(i);
            int charCount = Character.charCount(codePoint);
            if (isLatinTokenBoundary(codePoint)) {
                if (runStart >= 0) {
                    spans.add(new int[] {runStart, i});
                    runStart = -1;
                }
            } else if (runStart < 0) {
                runStart = i;
            }
            i += charCount;
        }
        if (runStart >= 0) {
            spans.add(new int[] {runStart, text.length()});
        }
        return spans;
    }

    /** 词边界：空白、CJK 汉字、或 CJK/全角标点（U+3000–303F、U+FF00–FFEF）。 */
    private static boolean isLatinTokenBoundary(int codePoint) {
        if (Character.isWhitespace(codePoint)) {
            return true;
        }
        if (isCjk(codePoint)) {
            return true;
        }
        Character.UnicodeBlock block = Character.UnicodeBlock.of(codePoint);
        return block == Character.UnicodeBlock.CJK_SYMBOLS_AND_PUNCTUATION
                || block == Character.UnicodeBlock.HALFWIDTH_AND_FULLWIDTH_FORMS;
    }

    private static List<int[]> cjkCharSpans(String text) {
        List<int[]> spans = new ArrayList<>();
        int i = 0;
        while (i < text.length()) {
            int codePoint = text.codePointAt(i);
            int charCount = Character.charCount(codePoint);
            if (isCjk(codePoint)) {
                spans.add(new int[] {i, i + charCount});
            }
            i += charCount;
        }
        return spans;
    }

    private static boolean isCjk(int codePoint) {
        Character.UnicodeScript script = Character.UnicodeScript.of(codePoint);
        return script == Character.UnicodeScript.HAN;
    }

    /** 找出 token 序列中连续命中 wordlist 的最大 run（半开区间 [start,end) 索引）。 */
    private static List<int[]> wordlistRuns(String text, List<int[]> spans, String language) {
        List<int[]> runs = new ArrayList<>();
        int runStart = -1;
        for (int i = 0; i < spans.size(); i++) {
            int[] span = spans.get(i);
            boolean inList = lookup(language, text, span) >= 0;
            if (inList) {
                if (runStart < 0) {
                    runStart = i;
                }
            } else if (runStart >= 0) {
                runs.add(new int[] {runStart, i});
                runStart = -1;
            }
        }
        if (runStart >= 0) {
            runs.add(new int[] {runStart, spans.size()});
        }
        return runs;
    }
}
