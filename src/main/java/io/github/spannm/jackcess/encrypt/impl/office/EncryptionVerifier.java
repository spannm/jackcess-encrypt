package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.encrypt.InvalidCryptoConfigurationException;
import io.github.spannm.jackcess.impl.ByteUtil;

import java.nio.ByteBuffer;

/**
 * The EncryptionVerifier structure (OC: 2.3.3) which follows the {@link EncryptionHeader} in the
 * encryption info of office encrypted databases.  It holds the salt used for key derivation plus
 * an encrypted random verifier and its encrypted hash, which together allow a given password to be
 * checked without decrypting the database itself.
 */
public class EncryptionVerifier {
    private static final int SALT_SIZE         = 16;
    private static final int ENC_VERIFIER_SIZE = 16;

    private final int        saltSize;
    private final byte[]     salt;
    private final byte[]     encryptedVerifier;
    private final int        verifierHashSize;
    private final byte[]     encryptedVerifierHash;

    /**
     * Reads a verifier from the given buffer.
     *
     * @param _buffer buffer positioned at the start of the EncryptionVerifier structure
     * @param _cryptoAlg the encryption algorithm of the database, which determines the length of
     *            the encrypted verifier hash
     * @throws InvalidCryptoConfigurationException if the salt size is not the expected one
     */
    public EncryptionVerifier(ByteBuffer _buffer, EncryptionHeader.CryptoAlgorithm _cryptoAlg) {
        // OC: 2.3.3 EncryptionVerifier Structure
        saltSize = _buffer.getInt();
        if (saltSize != SALT_SIZE) {
            throw new InvalidCryptoConfigurationException("salt size " + saltSize + " must be " + SALT_SIZE);
        }
        salt = ByteUtil.getBytes(_buffer, saltSize);
        encryptedVerifier = ByteUtil.getBytes(_buffer, ENC_VERIFIER_SIZE);
        verifierHashSize = _buffer.getInt();
        encryptedVerifierHash = ByteUtil.getBytes(_buffer, _cryptoAlg.getEncryptedVerifierHashLen());
    }

    /**
     * @return the size of the salt in bytes
     */
    public int getSaltSize() {
        return saltSize;
    }

    /**
     * @return the salt used for key derivation
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * @return the encrypted verifier bytes
     */
    public byte[] getEncryptedVerifier() {
        return encryptedVerifier;
    }

    /**
     * @return the size of the (unencrypted) verifier hash in bytes
     */
    public int getVerifierHashSize() {
        return verifierHashSize;
    }

    /**
     * @return the encrypted hash of the verifier bytes
     */
    public byte[] getEncryptedVerifierHash() {
        return encryptedVerifierHash;
    }

}
