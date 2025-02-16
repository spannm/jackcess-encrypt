package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.impl.ByteUtil;
import io.github.spannm.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;

public class ECMAStandardEncryptionProvider extends BlockCipherProvider {

    private static final Set<EncryptionHeader.CryptoAlgorithm> VALID_CRYPTO_ALGOS = EnumSet.of(
        EncryptionHeader.CryptoAlgorithm.AES_128, EncryptionHeader.CryptoAlgorithm.AES_192, EncryptionHeader.CryptoAlgorithm.AES_256);
    private static final Set<EncryptionHeader.HashAlgorithm>   VALID_HASH_ALGOS   = EnumSet.of(EncryptionHeader.HashAlgorithm.SHA1);
    private static final int                                   HASH_ITERATIONS    = 50000;

    private final int                                          hashIterations;
    private final EncryptionHeader                             header;
    private final EncryptionVerifier                           verifier;
    private final byte[]                                       baseHash;
    private final int                                          encKeyByteSize;

    public ECMAStandardEncryptionProvider(PageChannel _channel, byte[] _encodingKey, ByteBuffer _encProvBuf, byte[] _password) throws IOException {
        this(_channel, _encodingKey, _encProvBuf, _password, HASH_ITERATIONS);
    }

    protected ECMAStandardEncryptionProvider(PageChannel _channel, byte[] _encodingKey, ByteBuffer _encProvBuf, byte[] _password, int _hashIterations) throws IOException {
        super(_channel, _encodingKey);

        hashIterations = _hashIterations;

        // OC: 2.3.4.6
        header = EncryptionHeader.read(_encProvBuf, VALID_CRYPTO_ALGOS, VALID_HASH_ALGOS);

        verifier = new EncryptionVerifier(_encProvBuf, header.getCryptoAlgorithm());

        // OC: 2.3.4.7 (part 1)
        baseHash = hash(getDigest(), verifier.getSalt(), _password);
        encKeyByteSize = bits2bytes(header.getKeySize());
    }

    @Override
    protected Digest initDigest() {
        return new SHA1Digest();
    }

    @Override
    @SuppressWarnings("deprecation")
    protected BlockCipher initCipher() {
        return new AESEngine();
    }

    @Override
    protected KeyParameter computeCipherParams(int _pageNumber) {
        // when actually decrypting pages, we incorporate the "encoding key"
        return computeEncryptionKey(getEncodingKey(_pageNumber));
    }

    @Override
    protected boolean verifyPassword(byte[] _password) {

        // OC: 2.3.4.9
        BufferedBlockCipher cipher = decryptInit(getBlockCipher(), computeEncryptionKey(int2bytes(0)));

        byte[] lverifier = decryptBytes(cipher, verifier.getEncryptedVerifier());
        byte[] lverifierHash = fixToLength(decryptBytes(cipher, verifier.getEncryptedVerifierHash()), verifier.getVerifierHashSize());

        byte[] ltestHash = fixToLength(hash(getDigest(), lverifier), verifier.getVerifierHashSize());

        return Arrays.equals(lverifierHash, ltestHash);
    }

    private KeyParameter computeEncryptionKey(byte[] _blockBytes) {
        byte[] encKey = cryptDeriveKey(baseHash, _blockBytes, encKeyByteSize);
        return new KeyParameter(encKey);
    }

    private byte[] cryptDeriveKey(byte[] _baseHash, byte[] _blockBytes, int _keyByteLen) {
        Digest digest = getDigest();

        // OC: 2.3.4.7 (after part 1)
        byte[] iterHash = iterateHash(_baseHash, hashIterations);

        byte[] finalHash = hash(digest, iterHash, _blockBytes);

        byte[] x1 = hash(digest, genXBytes(finalHash, 0x36));
        byte[] x2 = hash(digest, genXBytes(finalHash, 0x5C));

        return fixToLength(ByteUtil.concat(x1, x2), _keyByteLen);
    }

    private static byte[] genXBytes(byte[] _finalHash, int _code) {
        byte[] x = fill(new byte[64], _code);

        for (int i = 0; i < _finalHash.length; ++i) {
            x[i] ^= _finalHash[i];
        }

        return x;
    }

}
