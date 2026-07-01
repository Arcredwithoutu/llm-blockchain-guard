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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * provider 客户端专用的极简 JSON 工具（core 零 Gson/Jackson）：只覆盖 R3 两个契约所需的请求拼装与响应抽取，
 * <b>非通用 JSON 解析器</b>。请求侧做 RFC 8259 字符串转义；响应侧做轻量对象切分 + 字段抽取。
 *
 * <p>设计取舍：响应来自自托管同信任域 Presidio / LLM Guard（字段结构稳定），不追求容错完备；
 * 任何抽取异常由调用方降级为空结果，故此处遇非预期结构返回空/默认值即可。</p>
 */
final class ProviderJson {

    private ProviderJson() {
    }

    /** 拼 {@code {"key":"value"}} 形式的单字段对象请求体（value 做 JSON 转义）。 */
    static String objectOf(String key, String value) {
        return "{\"" + key + "\":\"" + escape(value) + "\"}";
    }

    /** 拼 {@code {"k1":"v1","k2":"v2"}}（两个字符串字段；v 均做转义）。 */
    static String objectOf(String key1, String value1, String key2, String value2) {
        return "{\"" + key1 + "\":\"" + escape(value1) + "\",\""
                + key2 + "\":\"" + escape(value2) + "\"}";
    }

    /** RFC 8259 最小字符串转义（不引三方）。 */
    static String escape(String raw) {
        if (raw == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(raw.length() + 16);
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    /**
     * 解析 Presidio {@code /analyze} 响应：顶层 JSON 数组，每个对象含 entity_type/start/end/score。
     * 任一字段缺失的对象按默认值（type=""/-1/-1/0.0）补齐，不抛异常。
     */
    static List<ProviderEntity> parseAnalyzeArray(String body) {
        List<ProviderEntity> entities = new ArrayList<>();
        if (body == null) {
            return entities;
        }
        for (String object : splitTopLevelObjects(body)) {
            String type = stringField(object, "entity_type");
            int start = intField(object, "start", -1);
            int end = intField(object, "end", -1);
            double score = doubleField(object, "score", 0.0);
            entities.add(new ProviderEntity(type == null ? "" : type, start, end, score));
        }
        return entities;
    }

    /** 抽取布尔字段（如 LLM Guard {@code is_valid}）；缺失/非法返回默认值。 */
    static boolean boolField(String body, String key, boolean defaultValue) {
        String raw = rawAfterKey(body, key);
        if (raw == null) {
            return defaultValue;
        }
        if (raw.startsWith("true")) {
            return true;
        }
        if (raw.startsWith("false")) {
            return false;
        }
        return defaultValue;
    }

    /** 抽取字符串字段（如 LLM Guard {@code sanitized_prompt}）。 */
    static String stringField(String body, String key) {
        String raw = rawAfterKey(body, key);
        if (raw == null || raw.isEmpty() || raw.charAt(0) != '"') {
            return null;
        }
        return readQuoted(raw, 0);
    }

    /**
     * 抽取 {@code "key":{...}} 的对象值并解析为 {@code String → Double} map（如 LLM Guard {@code scanners}）。
     * 仅支持数字值（scanner 分值场景）；缺失/非对象返回空 map。
     */
    static Map<String, Double> numberMapField(String body, String key) {
        Map<String, Double> result = new LinkedHashMap<>();
        String raw = rawAfterKey(body, key);
        if (raw == null || raw.isEmpty() || raw.charAt(0) != '{') {
            return result;
        }
        String inner = sliceBalancedObject(raw);
        if (inner == null) {
            return result;
        }
        int i = 0;
        while (i < inner.length()) {
            int quote = inner.indexOf('"', i);
            if (quote < 0) {
                break;
            }
            int keyEnd = closingQuote(inner, quote);
            if (keyEnd < 0) {
                break;
            }
            String entryKey = readQuoted(inner, quote);
            int colon = inner.indexOf(':', keyEnd + 1);
            if (colon < 0) {
                break;
            }
            int j = colon + 1;
            while (j < inner.length() && Character.isWhitespace(inner.charAt(j))) {
                j++;
            }
            Double number = leadingNumber(inner.substring(j));
            if (number != null) {
                result.put(entryKey, number);
            }
            int comma = inner.indexOf(',', j);
            if (comma < 0) {
                break;
            }
            i = comma + 1;
        }
        return result;
    }

    /** 返回 openQuote 之后该 JSON 字符串的闭合引号下标（处理转义）；未闭合返回 -1。 */
    private static int closingQuote(String text, int openQuote) {
        for (int i = openQuote + 1; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\\') {
                i++;
                continue;
            }
            if (c == '"') {
                return i;
            }
        }
        return -1;
    }

    /** 取 {@code {...}} 起头的子串中第一个对象的内容（不含外层花括号），括号不平衡返回 null。 */
    private static String sliceBalancedObject(String raw) {
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return raw.substring(1, i);
                }
            }
        }
        return null;
    }

    private static int intField(String body, String key, int defaultValue) {
        String raw = rawAfterKey(body, key);
        Double number = leadingNumber(raw);
        return number == null ? defaultValue : (int) Math.round(number);
    }

    private static double doubleField(String body, String key, double defaultValue) {
        String raw = rawAfterKey(body, key);
        Double number = leadingNumber(raw);
        return number == null ? defaultValue : number;
    }

    /**
     * 把顶层数组切成各对象子串（按括号深度跟踪，忽略字符串内的括号/逗号）。
     * 非数组（不以 {@code [} 起头）时返回空列表。
     */
    private static List<String> splitTopLevelObjects(String body) {
        List<String> objects = new ArrayList<>();
        String trimmed = body.trim();
        int arrayStart = trimmed.indexOf('[');
        if (arrayStart < 0) {
            return objects;
        }
        int depth = 0;
        int objStart = -1;
        boolean inString = false;
        boolean escaped = false;
        for (int i = arrayStart + 1; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{') {
                if (depth == 0) {
                    objStart = i;
                }
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0 && objStart >= 0) {
                    objects.add(trimmed.substring(objStart, i + 1));
                    objStart = -1;
                }
            } else if (c == ']' && depth == 0) {
                break;
            }
        }
        return objects;
    }

    /** 返回 {@code "key"} 之后冒号后第一个非空白字符起的子串；找不到返回 null。 */
    private static String rawAfterKey(String body, String key) {
        if (body == null) {
            return null;
        }
        String needle = "\"" + key + "\"";
        int keyPos = body.indexOf(needle);
        if (keyPos < 0) {
            return null;
        }
        int colon = body.indexOf(':', keyPos + needle.length());
        if (colon < 0) {
            return null;
        }
        int i = colon + 1;
        while (i < body.length() && Character.isWhitespace(body.charAt(i))) {
            i++;
        }
        return i < body.length() ? body.substring(i) : null;
    }

    private static Double leadingNumber(String raw) {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        int i = 0;
        while (i < raw.length() && isNumberChar(raw.charAt(i))) {
            i++;
        }
        if (i == 0) {
            return null;
        }
        try {
            return Double.parseDouble(raw.substring(0, i));
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private static boolean isNumberChar(char c) {
        return (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E';
    }

    /** 读取从 quoteIndex 处引号开始的 JSON 字符串内容（去转义常见序列）。 */
    private static String readQuoted(String raw, int quoteIndex) {
        StringBuilder sb = new StringBuilder();
        for (int i = quoteIndex + 1; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\\' && i + 1 < raw.length()) {
                char next = raw.charAt(++i);
                switch (next) {
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    default -> sb.append(next);
                }
            } else if (c == '"') {
                return sb.toString();
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
