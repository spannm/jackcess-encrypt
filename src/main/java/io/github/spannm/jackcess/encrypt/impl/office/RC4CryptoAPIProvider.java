package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.encrypt.util.StreamCipherCompat;
import io.github.spannm.jackcess.encrypt.util.StreamCipherFactory;
import io.github.spannm.jackcess.impl.ByteUtil;
import io.github.spannm.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;

/**
 * Office encryption provider implementing "RC4 CryptoAPI encryption" (OC: 2.3.5).  Reads the
 * {@link EncryptionHeader} and {@link EncryptionVerifier} structures (restricted to RC4 with SHA-1)
 * and derives the per page RC4 key from the verifier salt, the password and the page specific
 * encoding key.
 */
public final class RC4CryptoAPIProvider extends StreamCipherProvider {
    private static final Set<EncryptionHeader.CryptoAlgorithm> VALID_CRYPTO_ALGOS = EnumSet.of(EncryptionHeader.CryptoAlgorithm.RC4);
    private static final Set<EncryptionHeader.HashAlgorithm>   VALID_HASH_ALGOS   = EnumSet.of(EncryptionHeader.HashAlgorithm.SHA1);

    private final EncryptionHeader                             header;
    private final EncryptionVerifier                           verifier;
    private final byte[]                                       baseHash;
    private final int                                          encKeyByteSize;

    /**
     * Creates a new provider reading its configuration from the given encryption info buffer.
     *
     * @param _channel the page channel of the database being opened
     * @param _encodingKey the encoding key read from the database header
     * @param _encProvBuf buffer positioned at the encryption provider info
     * @param _password the password bytes (UTF-16LE encoded)
     * @throws io.github.spannm.jackcess.encrypt.InvalidCryptoConfigurationException if the
     *             encryption info does not describe a valid RC4/SHA-1 configuration
     */
    public RC4CryptoAPIProvider(PageChannel _channel, byte[] _encodingKey, ByteBuffer _encProvBuf, byte[] _password) {
        super(_channel, _encodingKey);
        header = EncryptionHeader.read(_encProvBuf, VALID_CRYPTO_ALGOS, VALID_HASH_ALGOS);

        verifier = new EncryptionVerifier(_encProvBuf, header.getCryptoAlgorithm());

        // OC: 2.3.5.2 (part 1)
        baseHash = hash(getDigest(), verifier.getSalt(), _password);
        encKeyByteSize = bits2bytes(header.getKeySize());
    }

    @Override
    public boolean canEncodePartialPage() {
        // RC4 ciphers are not influenced by the page contents, so we can easily
        // encode part of the buffer.
        return true;
    }

    @Override
    protected Digest initDigest() {
        return new SHA1Digest();
    }

    @Override
    protected StreamCipherCompat initCipher() {
        return StreamCipherFactory.newRC4Engine();
    }

    @Override
    protected KeyParameter computeCipherParams(int _pageNumber) {
        // when actually decrypting pages, we incorporate the "encoding key"
        return computeEncryptionKey(getEncodingKey(_pageNumber));
    }

    private KeyParameter computeEncryptionKey(byte[] _blockBytes) {

        // OC: 2.3.5.2 (part 2)
        byte[] encKey = hash(getDigest(), baseHash, _blockBytes, encKeyByteSize);
        if (header.getKeySize() == 40) {
            encKey = ByteUtil.copyOf(encKey, bits2bytes(128));
        }
        return new KeyParameter(encKey);
    }

    @Override
    protected boolean verifyPassword(byte[] _password) {
        StreamCipherCompat lcipher = decryptInit(getStreamCipher(), computeEncryptionKey(int2bytes(0)));

        byte[] lverifier = decryptBytes(lcipher, verifier.getEncryptedVerifier());
        byte[] lverifierHash = fixToLength(decryptBytes(lcipher, verifier.getEncryptedVerifierHash()), verifier.getVerifierHashSize());

        byte[] ltestHash = fixToLength(hash(getDigest(), lverifier), verifier.getVerifierHashSize());

        return Arrays.equals(lverifierHash, ltestHash);
    }

}
