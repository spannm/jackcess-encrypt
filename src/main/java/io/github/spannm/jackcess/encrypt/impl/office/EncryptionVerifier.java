package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.encrypt.InvalidCryptoConfigurationException;
import io.github.spannm.jackcess.impl.ByteUtil;

import java.nio.ByteBuffer;

public class EncryptionVerifier {
    private static final int SALT_SIZE         = 16;
    private static final int ENC_VERIFIER_SIZE = 16;

    private final int        saltSize;
    private final byte[]     salt;
    private final byte[]     encryptedVerifier;
    private final int        verifierHashSize;
    private final byte[]     encryptedVerifierHash;

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

    public int getSaltSize() {
        return saltSize;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getEncryptedVerifier() {
        return encryptedVerifier;
    }

    public int getVerifierHashSize() {
        return verifierHashSize;
    }

    public byte[] getEncryptedVerifierHash() {
        return encryptedVerifierHash;
    }

}
