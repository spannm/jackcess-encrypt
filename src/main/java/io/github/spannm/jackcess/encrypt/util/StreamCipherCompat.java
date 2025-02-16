package io.github.spannm.jackcess.encrypt.util;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Alternate version of StreamCipher API which allows us to be handle both old
 * and new bouncycastle versions.
 *
 * @see org.bouncycastle.crypto.StreamCipher
 */
public interface StreamCipherCompat {
    String getAlgorithmName();

    void init(boolean forEncryption, CipherParameters params);

    byte returnByte(byte in);

    int processStreamBytes(byte[] in, int inOff, int len, byte[] out, int outOff);

    void reset();
}
