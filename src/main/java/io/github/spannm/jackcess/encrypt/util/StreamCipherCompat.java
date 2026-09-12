package io.github.spannm.jackcess.encrypt.util;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Alternate version of StreamCipher API which allows us to be handle both old
 * and new bouncycastle versions.
 *
 * @see org.bouncycastle.crypto.StreamCipher
 */
public interface StreamCipherCompat {
    /**
     * Returns the name of the algorithm this cipher implements.
     *
     * @return the algorithm name
     */
    String getAlgorithmName();

    /**
     * Initializes the cipher for encryption or decryption.
     *
     * @param forEncryption {@code true} to initialize for encryption, {@code false} for decryption
     * @param params the key and other parameters required by the cipher
     */
    void init(boolean forEncryption, CipherParameters params);

    /**
     * Encrypts or decrypts a single byte.
     *
     * @param in the byte to process
     * @return the processed byte
     */
    byte returnByte(byte in);

    /**
     * Encrypts or decrypts a block of bytes.
     *
     * @param in the input buffer
     * @param inOff offset of the first byte to process within the input buffer
     * @param len the number of bytes to process
     * @param out the output buffer receiving the processed bytes
     * @param outOff offset at which to start writing within the output buffer
     * @return the number of bytes written to the output buffer
     */
    int processStreamBytes(byte[] in, int inOff, int len, byte[] out, int outOff);

    /**
     * Resets the cipher to its state directly after initialization.
     */
    void reset();
}
