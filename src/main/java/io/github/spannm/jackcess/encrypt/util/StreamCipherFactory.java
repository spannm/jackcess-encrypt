package io.github.spannm.jackcess.encrypt.util;

/**
 * Factory for instantiating {@link StreamCipherCompat} instances.  Bouncy
 * Castle 1.51 made a binary incompatible change to the StreamCipher API.
 * This factory enables jackcess-encrypt to function with both the pre 1.51
 * API as well as the 1.51+ API.
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

    protected StreamCipherFactory() {
    }

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

    public abstract StreamCipherCompat newInstance();
}
