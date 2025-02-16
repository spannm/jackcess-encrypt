package io.github.spannm.jackcess.encrypt.util;

import org.bouncycastle.crypto.engines.RC4Engine;

/**
 * Simple Extension of {@link RC4Engine} which implements StreamCipherCompat
 * and allows jackcess-encrypt to work with 1.51+ versions of Bouncy Castle.
 */
public class RC4EngineCompat extends RC4Engine implements StreamCipherCompat {

    static {
        try {
            // this implementation expects the processBytes method to have an int
            // return type
            if (RC4Engine.class.getMethod("processBytes", byte[].class, int.class, int.class, byte[].class, int.class).getReturnType() != int.class) {
                throw new IllegalStateException("Wrong return type");
            }
        } catch (Exception _ex) {
            throw new IllegalStateException("Incompatible RC4Engine", _ex);
        }
    }

    /** StreamCipherFactory for this engine */
    public static final class Factory extends StreamCipherFactory {
        @Override
        public StreamCipherCompat newInstance() {
            return new RC4EngineCompat();
        }
    }

    public RC4EngineCompat() {
    }

    /**
     * @see RC4Engine#processBytes
     */
    @Override
    public int processStreamBytes(byte[] in, int inOff, int len, byte[] out, int outOff) {
        return processBytes(in, inOff, len, out, outOff);
    }
}
