package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.encrypt.util.StreamCipherCompat;
import io.github.spannm.jackcess.encrypt.util.StreamCipherFactory;
import io.github.spannm.jackcess.impl.ByteUtil;
import io.github.spannm.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Office encryption provider implementing "office binary document RC4 encryption" (OC: 2.3.6),
 * the scheme used by encryption provider version 1.1.  The key is derived from an MD5 digest of
 * the password and the header salt and combined with the page specific encoding key.
 */
public final class OfficeBinaryDocRC4Provider extends StreamCipherProvider {
    private final byte[] encVerifier     = new byte[16];
    private final byte[] encVerifierHash = new byte[16];
    private final byte[] baseHash;

    /**
     * Creates a new provider reading its configuration from the given encryption info buffer.
     *
     * @param _channel the page channel of the database being opened
     * @param _encodingKey the encoding key read from the database header
     * @param _encProvBuf buffer positioned at the encryption provider info
     * @param _password the password bytes (UTF-16LE encoded)
     */
    public OfficeBinaryDocRC4Provider(PageChannel _channel, byte[] _encodingKey, ByteBuffer _encProvBuf, byte[] _password) {
        super(_channel, _encodingKey);

        // OC: 2.3.6.1
        byte[] salt = new byte[16];
        _encProvBuf.get(salt);
        _encProvBuf.get(encVerifier);
        _encProvBuf.get(encVerifierHash);

        // OC: 2.3.6.2 (Part 1)
        byte[] fillHash = ByteUtil.concat(hash(getDigest(), _password, 5), salt);
        byte[] intBuf = new byte[336];
        for (int i = 0; i < intBuf.length; i += fillHash.length) {
            System.arraycopy(fillHash, 0, intBuf, i, fillHash.length);
        }

        baseHash = hash(getDigest(), intBuf, 5);
    }

    @Override
    public boolean canEncodePartialPage() {
        // RC4 ciphers are not influenced by the page contents, so we can easily
        // encode part of the buffer.
        return true;
    }

    @Override
    protected Digest initDigest() {
        return new MD5Digest();
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
        // OC: 2.3.6.2 (Part 2)
        byte[] encKey = hash(getDigest(), baseHash, _blockBytes, bits2bytes(128));
        return new KeyParameter(encKey);
    }

    @Override
    protected boolean verifyPassword(byte[] _password) {

        StreamCipherCompat cipher = decryptInit(getStreamCipher(), computeEncryptionKey(int2bytes(0)));

        byte[] verifier = decryptBytes(cipher, encVerifier);
        byte[] verifierHash = decryptBytes(cipher, encVerifierHash);

        byte[] testHash = hash(getDigest(), verifier);

        return Arrays.equals(verifierHash, testHash);
    }

}
