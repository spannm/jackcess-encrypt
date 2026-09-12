package io.github.spannm.jackcess.encrypt.util;

/**
 * Factory for instantiating {@link StreamCipherCompat} instances.  Bouncy
 * Castle 1.51 made a binary incompatible change to the StreamCipher API.
 * This factory shields the rest of the library from that difference by
 * locating a matching engine implementation reflectively at class load time.
 * <p>
 * The current distribution only ships the 1.51+ compatible implementation
 * ({@link RC4EngineCompat}).  The lookup of the legacy (1.50 and earlier)
 * implementation is retained as a fallback for setups which supply such a
 * class themselves; if neither can be loaded, class initialization fails with
 * an {@link IllegalStateException}.
 */
public abstract class StreamCipherFactory {
    /** compatible factory for RC4Engine instances */
    private static final StreamCipherFactory RC4_ENGINE_FACTORY;
    static {
        StreamCipherFactory factory = null;
        try {
            // first, attempt to load a 1.51+ compatible factory instance
            factory = loadFactory("io.github.spannm.jackcess.encrypt.util.RC4EngineCompat$Factory");
        } catch (Throwable _ex) {
            // failed, try legacy version
        }

        if (factory == null) {
            try {
                // now, attempt to load a 1.50 and earlier compatible factory instance
                factory = loadFactory("io.github.spannm.jackcess.encrypt.util.RC4EngineLegacy$Factory");
            } catch (Throwable _ex) {
                // sorry, no dice
                throw new IllegalStateException("Incompatible bouncycastle version", _ex);
            }
        }

        RC4_ENGINE_FACTORY = factory;
    }

    /**
     * Creates a new factory instance.
     */
    protected StreamCipherFactory() {
    }

    /**
     * Creates a new RC4 engine using the bouncycastle version found on the classpath.
     *
     * @return a new, uninitialized RC4 engine
     */
    public static StreamCipherCompat newRC4Engine() {
        return RC4_ENGINE_FACTORY.newInstance();
    }

    private static StreamCipherFactory loadFactory(String _className) throws Exception {
        Class<?> factoryClass = Class.forName(_className);
        StreamCipherFactory factory = (StreamCipherFactory) factoryClass.getDeclaredConstructor().newInstance();
        // verify that the engine is functional
        if (factory.newInstance() == null) {
            throw new IllegalStateException("EngineFactory " + _className + " not functional");
        }
        return factory;
    }

    /**
     * Creates a new stream cipher instance.
     *
     * @return a new, uninitialized stream cipher
     */
    public abstract StreamCipherCompat newInstance();
}
