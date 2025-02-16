/*
Copyright (c) 2010 Vladimir Berezniker

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package io.github.spannm.jackcess.encrypt.impl;

import io.github.spannm.jackcess.encrypt.util.StreamCipherCompat;
import io.github.spannm.jackcess.impl.ByteUtil;
import io.github.spannm.jackcess.impl.CodecHandler;
import io.github.spannm.jackcess.impl.PageChannel;
import io.github.spannm.jackcess.impl.TempBufferHolder;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Common CodecHandler support.
 *
 * @author Vladimir Berezniker
 */
public abstract class BaseCryptCodecHandler implements CodecHandler {

    public static final boolean              CIPHER_DECRYPT_MODE = false;
    public static final boolean              CIPHER_ENCRYPT_MODE = true;

    private final PageChannel                channel;
    private final byte[]                     encodingKey;
    private final KeyCache<CipherParameters> paramCache         =
        new KeyCache<>() {
            @Override
            protected CipherParameters computeKey(int _pageNumber) {
                return computeCipherParams(_pageNumber);
            }
        };
    private TempBufferHolder                 tempBufH;

    protected BaseCryptCodecHandler(PageChannel _channel, byte[] _encodingKey) {
        channel = _channel;
        encodingKey = _encodingKey;
    }

    protected CipherParameters getCipherParams(int _pageNumber) {
        return paramCache.get(_pageNumber);
    }

    protected byte[] getEncodingKey() {
        return encodingKey;
    }

    protected StreamCipherCompat getStreamCipher() {
        throw new UnsupportedOperationException();
    }

    protected BufferedBlockCipher getBlockCipher() {
        throw new UnsupportedOperationException();
    }

    protected ByteBuffer getTempBuffer() {
        if (tempBufH == null) {
            tempBufH = TempBufferHolder.newHolder(TempBufferHolder.Type.SOFT, true);
        }
        ByteBuffer tempBuf = tempBufH.getPageBuffer(channel);
        tempBuf.clear();
        return tempBuf;
    }

    /**
     * Decrypts the given buffer using a stream cipher.
     */
    protected void streamDecrypt(ByteBuffer _buffer, int _pageNumber) {
        StreamCipherCompat cipher = decryptInit(getStreamCipher(), getCipherParams(_pageNumber));

        byte[] array = _buffer.array();
        cipher.processStreamBytes(array, 0, array.length, array, 0);
    }

    /**
     * Encrypts the given buffer using a stream cipher and returns the encrypted
     * buffer.
     */
    protected ByteBuffer streamEncrypt(ByteBuffer _buffer, int _pageNumber, int _pageOffset) {
        StreamCipherCompat cipher = encryptInit(getStreamCipher(), getCipherParams(_pageNumber));

        // note, we always start encoding at offset 0 so that we apply the cipher
        // to the correct part of the stream. however, we can stop when we get to
        // the limit.
        int limit = _buffer.limit();
        ByteBuffer encodeBuf = getTempBuffer();
        cipher.processStreamBytes(_buffer.array(), 0, limit, encodeBuf.array(), 0);
        return encodeBuf;
    }

    /**
     * Decrypts the given buffer using a block cipher.
     */
    protected void blockDecrypt(ByteBuffer _inPage, ByteBuffer _outPage, int _pageNumber) {
        BufferedBlockCipher cipher = decryptInit(getBlockCipher(), getCipherParams(_pageNumber));

        try {
            byte[] inArray = _inPage.array();
            int inLen = inArray.length;
            byte[] outArray = _outPage.array();
            processBytesFully(cipher, inArray, fill(outArray, 0), inLen);
        } catch (InvalidCipherTextException _ex) {
            throw new IllegalStateException(_ex);
        }
    }

    /**
     * Encrypts the given buffer using a block cipher and returns the encrypted
     * buffer.
     */
    protected ByteBuffer blockEncrypt(ByteBuffer buffer, int pageNumber) {
        BufferedBlockCipher cipher = encryptInit(getBlockCipher(), getCipherParams(pageNumber));

        try {
            byte[] inArray = buffer.array();
            int inLen = buffer.limit();
            ByteBuffer encodeBuf = getTempBuffer();
            processBytesFully(cipher, inArray, fill(encodeBuf.array(), 0), inLen);
            return encodeBuf;
        } catch (InvalidCipherTextException _ex) {
            throw new IllegalStateException(_ex);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName();
    }

    /**
     * Inits the given cipher for decryption with the given params.
     */
    protected static StreamCipherCompat decryptInit(StreamCipherCompat cipher, CipherParameters params) {
        cipher.init(CIPHER_DECRYPT_MODE, params);
        return cipher;
    }

    /**
     * Inits the given cipher for encryption with the given params.
     */
    protected static StreamCipherCompat encryptInit(StreamCipherCompat cipher, CipherParameters params) {
        cipher.init(CIPHER_ENCRYPT_MODE, params);
        return cipher;
    }

    /**
     * Inits the given cipher for decryption with the given params.
     */
    protected static BufferedBlockCipher decryptInit(BufferedBlockCipher cipher, CipherParameters params) {
        cipher.init(CIPHER_DECRYPT_MODE, params);
        return cipher;
    }

    /**
     * Inits the given cipher for encryption with the given params.
     */
    protected static BufferedBlockCipher encryptInit(BufferedBlockCipher cipher, CipherParameters params) {
        cipher.init(CIPHER_ENCRYPT_MODE, params);
        return cipher;
    }

    /**
     * Decrypts the given bytes using a stream cipher into a new byte[].
     */
    protected static byte[] decryptBytes(StreamCipherCompat _cipher, byte[] _encBytes) {
        byte[] bytes = new byte[_encBytes.length];
        _cipher.processStreamBytes(_encBytes, 0, _encBytes.length, bytes, 0);
        return bytes;
    }

    /**
     * Decrypts the given bytes using a block cipher configured with the given
     * key and IV into a new byte[].
     */
    protected byte[] blockDecryptBytes(byte[] keyBytes, byte[] iv, byte[] encBytes) {
        BufferedBlockCipher cipher = decryptInit(getBlockCipher(), new ParametersWithIV(new KeyParameter(keyBytes), iv));
        return decryptBytes(cipher, encBytes);
    }

    /**
     * Decrypts the given bytes using a block cipher into a new byte[].
     */
    protected static byte[] decryptBytes(BufferedBlockCipher _cipher, byte[] _encBytes) {
        try {
            int inLen = _encBytes.length;
            return processBytesFully(_cipher, _encBytes, new byte[inLen], inLen);
        } catch (InvalidCipherTextException _ex) {
            throw new IllegalStateException(_ex);
        }
    }

    /**
     * Gets the encoding key combined with the given page number.
     */
    protected byte[] getEncodingKey(int pageNumber) {
        return applyPageNumber(getEncodingKey(), 0, pageNumber);
    }

    /**
     * Reads and returns the header page (page 0) from the given pageChannel.
     */
    protected static ByteBuffer readHeaderPage(PageChannel pageChannel) throws IOException {
        ByteBuffer buffer = pageChannel.createPageBuffer();
        pageChannel.readPage(buffer, 0);
        return buffer;
    }

    /**
     * Returns a copy of the given key with the bytes of the given pageNumber
     * applied at the given offset using XOR.
     */
    public static byte[] applyPageNumber(byte[] key, int offset, int pageNumber) {

        byte[] tmp = ByteUtil.copyOf(key, key.length);
        ByteBuffer bb = wrap(tmp);
        bb.position(offset);
        bb.putInt(pageNumber);

        for (int i = offset; i < (offset + 4); ++i) {
            tmp[i] ^= key[i];
        }

        return tmp;
    }

    /**
     * Hashes the given bytes using the given digest and returns the result.
     */
    public static byte[] hash(Digest digest, byte[] bytes) {
        return hash(digest, bytes, null, 0);
    }

    /**
     * Hashes the given bytes1 and bytes2 using the given digest and returns the
     * result.
     */
    public static byte[] hash(Digest digest, byte[] bytes1, byte[] bytes2) {
        return hash(digest, bytes1, bytes2, 0);
    }

    /**
     * Hashes the given bytes using the given digest and returns the hash fixed
     * to the given length.
     */
    public static byte[] hash(Digest digest, byte[] bytes, int resultLen) {
        return hash(digest, bytes, null, resultLen);
    }

    /**
     * Hashes the given bytes1 and bytes2 using the given digest and returns the
     * hash fixed to the given length.
     */
    public static byte[] hash(Digest _digest, byte[] _bytes1, byte[] _bytes2, int _resultLen) {
        _digest.reset();

        _digest.update(_bytes1, 0, _bytes1.length);

        if (_bytes2 != null) {
            _digest.update(_bytes2, 0, _bytes2.length);
        }

        // Get digest value
        byte[] digestBytes = new byte[_digest.getDigestSize()];
        _digest.doFinal(digestBytes, 0);

        // adjust to desired length
        if (_resultLen > 0) {
            digestBytes = fixToLength(digestBytes, _resultLen);
        }

        return digestBytes;
    }

    /**
     * @return a byte array of the given length, truncating or padding the given
     * byte array as necessary.
     */
    public static byte[] fixToLength(byte[] _bytes, int _len) {
        return fixToLength(_bytes, _len, 0);
    }

    /**
     * @return a byte array of the given length, truncating or padding the given
     * byte array as necessary using the given padByte.
     */
    @SuppressWarnings("PMD.ParameterAssignment")
    public static byte[] fixToLength(byte[] _bytes, int _len, int _padByte) {
        int byteLen = _bytes.length;
        if (byteLen != _len) {
            _bytes = ByteUtil.copyOf(_bytes, _len);
            if (byteLen < _len) {
                Arrays.fill(_bytes, byteLen, _len, (byte) _padByte);
            }
        }
        return _bytes;
    }

    /**
     * @return a new ByteBuffer wrapping the given bytes with the appropriate
     *         byte order
     */
    public static ByteBuffer wrap(byte[] _bytes) {
        return ByteBuffer.wrap(_bytes).order(PageChannel.DEFAULT_BYTE_ORDER);
    }

    /**
     * Fills the given array with the given value and returns it.
     */
    public static byte[] fill(byte[] _bytes, int _value) {
        Arrays.fill(_bytes, (byte) _value);
        return _bytes;
    }

    /**
     * Processes all the bytes for the given block cipher.
     */
    protected static byte[] processBytesFully(BufferedBlockCipher _cipher, byte[] _inArray, byte[] _outArray, int _inLen) throws InvalidCipherTextException {
        int outLen = _cipher.processBytes(_inArray, 0, _inLen, _outArray, 0);
        _cipher.doFinal(_outArray, outLen);
        return _outArray;
    }

    /**
     * @return {@code true} if the given bytes are all 0, {@code false}
     *         otherwise
     */
    protected static boolean isBlankKey(byte[] _key) {
        for (byte byteVal : _key) {
            if (byteVal != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Generates the cipher parameters for the given page number.
     */
    protected abstract CipherParameters computeCipherParams(int pageNumber);

}
