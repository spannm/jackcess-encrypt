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
 * Common CodecHandler support.  Handles the parts shared by all supported encryption schemes:
 * caching of the per page cipher parameters, encrypting and decrypting page buffers with either a
 * stream or a block cipher and the various hashing and byte array helpers used during key
 * derivation.  Subclasses provide the actual cipher and the scheme specific key computation via
 * {@link #computeCipherParams}.
 *
 * @author Vladimir Berezniker
 */
public abstract class BaseCryptCodecHandler implements CodecHandler {

    /** cipher init mode constant for decryption */
    public static final boolean              CIPHER_DECRYPT_MODE = false;
    /** cipher init mode constant for encryption */
    public static final boolean              CIPHER_ENCRYPT_MODE = true;

    private final PageChannel                channel;
    private final byte[]                     encodingKey;
    private KeyCache<CipherParameters>       paramCache;
    private TempBufferHolder                 tempBufH;

    /**
     * Creates a new handler for the given page channel.
     *
     * @param _channel the page channel of the database being read or written
     * @param _encodingKey the database specific encoding key, may be {@code null} if the encryption
     *            scheme does not use one
     */
    protected BaseCryptCodecHandler(PageChannel _channel, byte[] _encodingKey) {
        channel = _channel;
        encodingKey = _encodingKey;
    }

    /**
     * Returns the (cached) cipher parameters for the given page.
     *
     * @param _pageNumber the database page number
     * @return the cipher parameters to use for the given page
     */
    protected CipherParameters getCipherParams(int _pageNumber) {
        if (paramCache == null) {
            paramCache = new KeyCache<CipherParameters>() {
                @Override
                protected CipherParameters computeKey(int _pageNum) {
                    return computeCipherParams(_pageNum);
                }
            };
        }
        return paramCache.get(_pageNumber);
    }

    /**
     * @return the database specific encoding key, may be {@code null}
     */
    protected byte[] getEncodingKey() {
        return encodingKey;
    }

    /**
     * Returns the stream cipher used by this handler.
     *
     * @return the stream cipher instance
     * @throws UnsupportedOperationException if this handler does not use a stream cipher
     */
    protected StreamCipherCompat getStreamCipher() {
        throw new UnsupportedOperationException();
    }

    /**
     * Returns the block cipher used by this handler.
     *
     * @return the block cipher instance
     * @throws UnsupportedOperationException if this handler does not use a block cipher
     */
    protected BufferedBlockCipher getBlockCipher() {
        throw new UnsupportedOperationException();
    }

    /**
     * Returns a cleared, page sized scratch buffer owned by this handler.
     *
     * @return a temporary page buffer
     */
    protected ByteBuffer getTempBuffer() {
        if (tempBufH == null) {
            tempBufH = TempBufferHolder.newHolder(TempBufferHolder.Type.SOFT, true);
        }
        ByteBuffer tempBuf = tempBufH.getPageBuffer(channel);
        tempBuf.clear();
        return tempBuf;
    }

    /**
     * Decrypts the given buffer in place using a stream cipher.
     *
     * @param _buffer the page buffer to decrypt, decrypted in place
     * @param _pageNumber the number of the page contained in the buffer
     */
    protected void streamDecrypt(ByteBuffer _buffer, int _pageNumber) {
        StreamCipherCompat cipher = decryptInit(getStreamCipher(), getCipherParams(_pageNumber));

        byte[] array = _buffer.array();
        cipher.processStreamBytes(array, 0, array.length, array, 0);
    }

    /**
     * Encrypts the given buffer using a stream cipher and returns the encrypted
     * buffer.  Encryption always starts at offset 0 of the page so that the cipher stream stays
     * aligned with the page contents, hence the given page offset is not used to skip any input.
     *
     * @param _buffer the page buffer to encrypt
     * @param _pageNumber the number of the page contained in the buffer
     * @param _pageOffset the offset within the page at which the modified data starts
     * @return a temporary buffer holding the encrypted page
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
     *
     * @param _inPage the buffer holding the encrypted page
     * @param _outPage the buffer receiving the decrypted page
     * @param _pageNumber the number of the page contained in the buffer
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
     *
     * @param buffer the page buffer to encrypt
     * @param pageNumber the number of the page contained in the buffer
     * @return a temporary buffer holding the encrypted page
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
     *
     * @param cipher the cipher to initialize
     * @param params the cipher parameters (key and, if applicable, IV)
     * @return the given cipher
     */
    protected static StreamCipherCompat decryptInit(StreamCipherCompat cipher, CipherParameters params) {
        cipher.init(CIPHER_DECRYPT_MODE, params);
        return cipher;
    }

    /**
     * Inits the given cipher for encryption with the given params.
     *
     * @param cipher the cipher to initialize
     * @param params the cipher parameters (key and, if applicable, IV)
     * @return the given cipher
     */
    protected static StreamCipherCompat encryptInit(StreamCipherCompat cipher, CipherParameters params) {
        cipher.init(CIPHER_ENCRYPT_MODE, params);
        return cipher;
    }

    /**
     * Inits the given cipher for decryption with the given params.
     *
     * @param cipher the cipher to initialize
     * @param params the cipher parameters (key and, if applicable, IV)
     * @return the given cipher
     */
    protected static BufferedBlockCipher decryptInit(BufferedBlockCipher cipher, CipherParameters params) {
        cipher.init(CIPHER_DECRYPT_MODE, params);
        return cipher;
    }

    /**
     * Inits the given cipher for encryption with the given params.
     *
     * @param cipher the cipher to initialize
     * @param params the cipher parameters (key and, if applicable, IV)
     * @return the given cipher
     */
    protected static BufferedBlockCipher encryptInit(BufferedBlockCipher cipher, CipherParameters params) {
        cipher.init(CIPHER_ENCRYPT_MODE, params);
        return cipher;
    }

    /**
     * Decrypts the given bytes using a stream cipher into a new byte[].
     *
     * @param _cipher the initialized stream cipher
     * @param _encBytes the encrypted bytes
     * @return a new array with the decrypted bytes
     */
    protected static byte[] decryptBytes(StreamCipherCompat _cipher, byte[] _encBytes) {
        byte[] bytes = new byte[_encBytes.length];
        _cipher.processStreamBytes(_encBytes, 0, _encBytes.length, bytes, 0);
        return bytes;
    }

    /**
     * Decrypts the given bytes using a block cipher configured with the given
     * key and IV into a new byte[].
     *
     * @param keyBytes the cipher key
     * @param iv the initialization vector
     * @param encBytes the encrypted bytes
     * @return a new array with the decrypted bytes
     */
    protected byte[] blockDecryptBytes(byte[] keyBytes, byte[] iv, byte[] encBytes) {
        BufferedBlockCipher cipher = decryptInit(getBlockCipher(), new ParametersWithIV(new KeyParameter(keyBytes), iv));
        return decryptBytes(cipher, encBytes);
    }

    /**
     * Decrypts the given bytes using a block cipher into a new byte[].
     *
     * @param _cipher the initialized block cipher
     * @param _encBytes the encrypted bytes
     * @return a new array with the decrypted bytes
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
     *
     * @param pageNumber the database page number
     * @return a new array with the page number applied to the encoding key
     */
    protected byte[] getEncodingKey(int pageNumber) {
        return applyPageNumber(getEncodingKey(), 0, pageNumber);
    }

    /**
     * Reads and returns the header page (page 0) from the given pageChannel.
     *
     * @param pageChannel the page channel to read from
     * @return a buffer holding the (still encoded) header page
     * @throws IOException if the page could not be read
     */
    protected static ByteBuffer readHeaderPage(PageChannel pageChannel) throws IOException {
        ByteBuffer buffer = pageChannel.createPageBuffer();
        pageChannel.readPage(buffer, 0);
        return buffer;
    }

    /**
     * Returns a copy of the given key with the bytes of the given pageNumber
     * applied at the given offset using XOR.
     *
     * @param key the base key
     * @param offset the offset within the key at which the page number is applied
     * @param pageNumber the database page number
     * @return a new array holding the modified key
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
     *
     * @param digest the digest to use
     * @param bytes the bytes to hash
     * @return the hash value
     */
    public static byte[] hash(Digest digest, byte[] bytes) {
        return hash(digest, bytes, null, 0);
    }

    /**
     * Hashes the given bytes1 and bytes2 using the given digest and returns the
     * result.
     *
     * @param digest the digest to use
     * @param bytes1 the first bytes to hash
     * @param bytes2 the second bytes to hash
     * @return the hash value
     */
    public static byte[] hash(Digest digest, byte[] bytes1, byte[] bytes2) {
        return hash(digest, bytes1, bytes2, 0);
    }

    /**
     * Hashes the given bytes using the given digest and returns the hash fixed
     * to the given length.
     *
     * @param digest the digest to use
     * @param bytes the bytes to hash
     * @param resultLen the desired length of the result, {@code 0} for the natural digest length
     * @return the hash value
     */
    public static byte[] hash(Digest digest, byte[] bytes, int resultLen) {
        return hash(digest, bytes, null, resultLen);
    }

    /**
     * Hashes the given bytes1 and bytes2 using the given digest and returns the
     * hash fixed to the given length.
     *
     * @param _digest the digest to use
     * @param _bytes1 the first bytes to hash
     * @param _bytes2 the second bytes to hash, may be {@code null}
     * @param _resultLen the desired length of the result, {@code 0} for the natural digest length
     * @return the hash value
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
     * @param _bytes the source bytes
     * @param _len the desired length
     * @return a byte array of the given length, truncating or padding the given
     * byte array as necessary.
     */
    public static byte[] fixToLength(byte[] _bytes, int _len) {
        return fixToLength(_bytes, _len, 0);
    }

    /**
     * @param _bytes the source bytes
     * @param _len the desired length
     * @param _padByte the byte value used for padding
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
     * @param _bytes the bytes to wrap
     * @return a new ByteBuffer wrapping the given bytes with the appropriate
     *         byte order
     */
    public static ByteBuffer wrap(byte[] _bytes) {
        return ByteBuffer.wrap(_bytes).order(PageChannel.DEFAULT_BYTE_ORDER);
    }

    /**
     * Fills the given array with the given value and returns it.
     *
     * @param _bytes the array to fill
     * @param _value the value written to every position of the array
     * @return the given array
     */
    public static byte[] fill(byte[] _bytes, int _value) {
        Arrays.fill(_bytes, (byte) _value);
        return _bytes;
    }

    /**
     * Processes all the bytes for the given block cipher.
     *
     * @param _cipher the initialized block cipher
     * @param _inArray the input bytes
     * @param _outArray the array receiving the processed bytes
     * @param _inLen the number of input bytes to process
     * @return the given output array
     * @throws InvalidCipherTextException if the cipher could not finalize the data
     */
    protected static byte[] processBytesFully(BufferedBlockCipher _cipher, byte[] _inArray, byte[] _outArray, int _inLen) throws InvalidCipherTextException {
        int outLen = _cipher.processBytes(_inArray, 0, _inLen, _outArray, 0);
        _cipher.doFinal(_outArray, outLen);
        return _outArray;
    }

    /**
     * @param _key the key bytes to test
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
     *
     * @param pageNumber the database page number
     * @return the cipher parameters to use for the given page
     */
    protected abstract CipherParameters computeCipherParams(int pageNumber);

}
