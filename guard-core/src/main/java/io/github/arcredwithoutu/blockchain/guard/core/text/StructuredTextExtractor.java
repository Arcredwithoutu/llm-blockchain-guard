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

package io.github.arcredwithoutu.blockchain.guard.core.text;

import java.util.ArrayList;
import java.util.List;

/**
 * 结构化输入字段级提取（设计 §8.10）：对合法 JSON 递归遍历，产出每个 string value 在
 * <b>原文</b>中的精确 span（供各 Scanner 把命中映射回原文、mask 保结构换值）。
 *
 * <p>实现为自研轻量 JSON value-span tokenizer——只定位 string value 的起止下标，不做完整反序列化，
 * 不引入任何三方依赖（core 零 Gson/Jackson）。解析失败（非 JSON / 结构残缺）时退回单个「全文 field」
 * （{@code key == null}，整段文本作为一个待扫描值）。</p>
 */
public final class StructuredTextExtractor {

    /**
     * 单个被提取字段。
     *
     * @param path       从根到该值的点分路径（数组元素以 {@code [i]} 表示）；全文 fallback 时为 {@code null}
     * @param key        直接父对象中的键名；数组元素或全文 fallback 时为 {@code null}
     * @param value      原文中的 value 子串（不含外层引号）
     * @param valueStart value 在原文中的起始下标（含，指向首字符）
     * @param valueEnd   value 在原文中的结束下标（不含）
     */
    public record Field(String path, String key, String value, int valueStart, int valueEnd) {
    }

    private StructuredTextExtractor() {
    }

    /** 提取 JSON string value 字段；非 JSON 退回单个全文 field。 */
    public static List<Field> extract(String text) {
        if (text == null || text.isEmpty()) {
            return List.of(new Field(null, null, text == null ? "" : text, 0, 0));
        }
        List<Field> fields = new ArrayList<>();
        Parser parser = new Parser(text, fields);
        try {
            int pos = parser.skipWs(0);
            char c = text.charAt(pos);
            if (c != '{' && c != '[') {
                return wholeText(text);
            }
            int end = parser.parseValue(pos, "");
            // 解析须恰好消费到尾部（允许尾随空白），否则视为非法 JSON。
            if (parser.skipWs(end) != text.length()) {
                return wholeText(text);
            }
            return fields;
        } catch (JsonParseException e) {
            return wholeText(text);
        }
    }

    private static List<Field> wholeText(String text) {
        return List.of(new Field(null, null, text, 0, text.length()));
    }

    /** 仅定位 string value span 的递归下降解析器；遇非法结构抛 {@link JsonParseException}。 */
    private static final class Parser {

        private final String text;
        private final int length;
        private final List<Field> out;

        Parser(String text, List<Field> out) {
            this.text = text;
            this.length = text.length();
            this.out = out;
        }

        /** 解析 pos 处的一个 value，返回其结束后的下标。命中 string 时把 span 记入 {@code out}。 */
        int parseValue(int pos, String path) {
            pos = skipWs(pos);
            char c = charAt(pos);
            return switch (c) {
                case '{' -> parseObject(pos, path);
                case '[' -> parseArray(pos, path);
                case '"' -> parseStringValue(pos, path, null);
                default -> parsePrimitive(pos);
            };
        }

        private int parseObject(int pos, String path) {
            pos = skipWs(pos + 1);
            if (charAt(pos) == '}') {
                return pos + 1;
            }
            while (true) {
                pos = skipWs(pos);
                if (charAt(pos) != '"') {
                    throw new JsonParseException();
                }
                int[] keySpan = readString(pos);
                String key = unescapeKey(text.substring(keySpan[0] + 1, keySpan[1] - 1));
                pos = skipWs(keySpan[1]);
                if (charAt(pos) != ':') {
                    throw new JsonParseException();
                }
                String childPath = path.isEmpty() ? key : path + "." + key;
                pos = skipWs(pos + 1);
                if (charAt(pos) == '"') {
                    pos = parseStringValue(pos, childPath, key);
                } else {
                    pos = parseValue(pos, childPath);
                }
                pos = skipWs(pos);
                char sep = charAt(pos);
                if (sep == ',') {
                    pos = pos + 1;
                } else if (sep == '}') {
                    return pos + 1;
                } else {
                    throw new JsonParseException();
                }
            }
        }

        private int parseArray(int pos, String path) {
            pos = skipWs(pos + 1);
            if (charAt(pos) == ']') {
                return pos + 1;
            }
            int index = 0;
            while (true) {
                String childPath = path + "[" + index + "]";
                pos = skipWs(pos);
                if (charAt(pos) == '"') {
                    pos = parseStringValue(pos, childPath, null);
                } else {
                    pos = parseValue(pos, childPath);
                }
                pos = skipWs(pos);
                char sep = charAt(pos);
                if (sep == ',') {
                    pos = pos + 1;
                    index++;
                } else if (sep == ']') {
                    return pos + 1;
                } else {
                    throw new JsonParseException();
                }
            }
        }

        private int parseStringValue(int pos, String path, String key) {
            int[] span = readString(pos);
            int valueStart = span[0] + 1;
            int valueEnd = span[1] - 1;
            out.add(new Field(path, key, text.substring(valueStart, valueEnd), valueStart, valueEnd));
            return span[1];
        }

        /** 读取 pos 处（必为 {@code "}）的字符串，返回 [起始引号下标, 结束引号后下标]。处理转义。 */
        private int[] readString(int pos) {
            if (charAt(pos) != '"') {
                throw new JsonParseException();
            }
            int i = pos + 1;
            while (i < length) {
                char c = text.charAt(i);
                if (c == '\\') {
                    i += 2;
                    continue;
                }
                if (c == '"') {
                    return new int[] {pos, i + 1};
                }
                i++;
            }
            throw new JsonParseException();
        }

        /** 解析 number/true/false/null：跳过直到分隔符；不记录 span（只关心 string value）。 */
        private int parsePrimitive(int pos) {
            int i = pos;
            while (i < length) {
                char c = text.charAt(i);
                if (c == ',' || c == '}' || c == ']' || Character.isWhitespace(c)) {
                    break;
                }
                i++;
            }
            if (i == pos) {
                throw new JsonParseException();
            }
            return i;
        }

        int skipWs(int pos) {
            int i = pos;
            while (i < length && Character.isWhitespace(text.charAt(i))) {
                i++;
            }
            return i;
        }

        private char charAt(int pos) {
            if (pos >= length) {
                throw new JsonParseException();
            }
            return text.charAt(pos);
        }
    }

    /** key 去转义仅处理常见转义，保持轻量；value 保留原文不去转义（span 指向原文）。 */
    private static String unescapeKey(String raw) {
        if (raw.indexOf('\\') < 0) {
            return raw;
        }
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\\' && i + 1 < raw.length()) {
                sb.append(raw.charAt(++i));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static final class JsonParseException extends RuntimeException {
        JsonParseException() {
            super(null, null, false, false);
        }
    }
}
