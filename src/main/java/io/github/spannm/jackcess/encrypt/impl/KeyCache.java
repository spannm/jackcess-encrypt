package io.github.spannm.jackcess.encrypt.impl;

import java.util.LinkedHashMap;
import java.util.Map;

public abstract class KeyCache<K> {
    private static final int MAX_KEY_CACHE_SIZE = 5;

    private final KeyMap<K>  map               = new KeyMap<>();

    protected KeyCache() {
    }

    public K get(int _pageNumber) {
        Integer pageNumKey = _pageNumber;
        K key = map.get(pageNumKey);
        if (key == null) {
            key = computeKey(_pageNumber);
            map.put(pageNumKey, key);
        }
        return key;
    }

    protected abstract K computeKey(int pageNumber);

    private static final class KeyMap<K> extends LinkedHashMap<Integer, K> {
        private static final long serialVersionUID = 0L;

        private KeyMap() {
            super(16, 0.75f, true);
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<Integer, K> eldest) {
            return size() > MAX_KEY_CACHE_SIZE;
        }
    }

}
