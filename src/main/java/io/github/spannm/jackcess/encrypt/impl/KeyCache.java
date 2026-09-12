package io.github.spannm.jackcess.encrypt.impl;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Small LRU cache for the per page encryption keys/cipher parameters.  Since every database page
 * uses a key derived from the page number, and pages are usually accessed in a locality friendly
 * manner, caching the most recently computed keys avoids repeating the (comparatively expensive)
 * key derivation for every single page access.
 *
 * @param <K> the type of the cached key
 */
public abstract class KeyCache<K> {
    private static final int MAX_KEY_CACHE_SIZE = 5;

    private final KeyMap<K>  map               = new KeyMap<>();

    /**
     * Creates a new, empty cache.
     */
    protected KeyCache() {
    }

    /**
     * Returns the key for the given page, computing and caching it if necessary.
     *
     * @param _pageNumber the database page number
     * @return the key for the given page
     */
    public K get(int _pageNumber) {
        Integer pageNumKey = _pageNumber;
        K key = map.get(pageNumKey);
        if (key == null) {
            key = computeKey(_pageNumber);
            map.put(pageNumKey, key);
        }
        return key;
    }

    /**
     * Computes the key for the given page.
     *
     * @param pageNumber the database page number
     * @return the newly computed key
     */
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
