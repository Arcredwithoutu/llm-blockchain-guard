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

package io.github.arcredwithoutu.blockchain.guard.core.codec;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class Bip39Wordlists {

    private static final Map<String, List<String>> WORDLISTS = new ConcurrentHashMap<>();
    private static final Map<String, Map<String, Integer>> INDEX = new ConcurrentHashMap<>();

    private Bip39Wordlists() {
    }

    public static List<String> english() { return wordlist("english"); }

    public static List<String> wordlist(String language) {
        return WORDLISTS.computeIfAbsent(language, Bip39Wordlists::load);
    }

    /** 返回词在 wordlist 中的 11-bit 索引；不存在返回 -1。 */
    public static int indexOf(String language, String word) {
        wordlist(language);
        return INDEX.getOrDefault(language, Map.of()).getOrDefault(word, -1);
    }

    private static List<String> load(String language) {
        List<String> words = new ArrayList<>(2048);
        String path = "/guard/bip39/" + language + ".txt";
        try (InputStream in = Bip39Wordlists.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException("BIP39 wordlist not found on classpath: " + path);
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                String w = line.trim();
                if (!w.isEmpty()) {
                    words.add(w);
                }
            }
        } catch (java.io.IOException e) {
            throw new IllegalStateException("Failed to load BIP39 wordlist: " + language, e);
        }
        Map<String, Integer> idx = new HashMap<>(words.size() * 2);
        for (int i = 0; i < words.size(); i++) {
            idx.put(words.get(i), i);
        }
        INDEX.put(language, idx);
        return words;
    }
}
