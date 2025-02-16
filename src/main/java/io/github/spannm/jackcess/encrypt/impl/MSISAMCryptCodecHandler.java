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

import io.github.spannm.jackcess.encrypt.InvalidCredentialsException;
import io.github.spannm.jackcess.encrypt.util.StreamCipherCompat;
import io.github.spannm.jackcess.impl.*;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.function.Supplier;

/**
 * CodecHandler for MSISAM databases.
 *
 * @author Vladimir Berezniker
 */
public class MSISAMCryptCodecHandler extends BaseJetCryptCodecHandler {
    private static final int SALT_OFFSET               = 0x72;
    private static final int CRYPT_CHECK_START         = 0x2e9;
    private static final int ENCRYPTION_FLAGS_OFFSET   = 0x298;
    private static final int SALT_LENGTH               = 0x4;
    private static final int PASSWORD_LENGTH           = 0x28;
    private static final int USE_SHA1                  = 0x20;
    private static final int PASSWORD_DIGEST_LENGTH    = 0x10;
    private static final int MSISAM_MAX_ENCRYPTED_PAGE = 0xE;
    // Modern encryption using hashing
    private static final int NEW_ENCRYPTION            = 0x6;
    private static final int TRAILING_PWD_LEN          = 20;

    private final byte[]     baseHash;

    MSISAMCryptCodecHandler(PageChannel _channel, String _password, Charset _charset, ByteBuffer _buffer) throws IOException {
        super(_channel, null);

        byte[] salt = ByteUtil.getBytes(_buffer, SALT_OFFSET, 8);

        // create decryption key parts
        byte[] pwdDigest = createPasswordDigest(_buffer, _password, _charset);
        byte[] baseSalt = ByteUtil.copyOf(salt, SALT_LENGTH);

        // check password hash using decryption of a known sequence
        verifyPassword(_buffer, ByteUtil.concat(pwdDigest, salt), baseSalt);

        // create final key
        baseHash = ByteUtil.concat(pwdDigest, baseSalt);
    }

    public static CodecHandler create(Supplier<String> _callback, PageChannel _channel, Charset _charset) throws IOException {
        ByteBuffer buffer = readHeaderPage(_channel);

        if ((buffer.get(ENCRYPTION_FLAGS_OFFSET) & NEW_ENCRYPTION) != 0) {
            return new MSISAMCryptCodecHandler(_channel, _callback.get(), _charset, buffer);
        }

        // old MSISAM dbs use jet-style encryption w/ a different key
        return new JetCryptCodecHandler(_channel, getOldDecryptionKey(buffer, _channel.getFormat())) {
            @Override
            protected int getMaxEncodedPage() {
                return MSISAM_MAX_ENCRYPTED_PAGE;
            }
        };
    }

    @Override
    protected KeyParameter computeCipherParams(int _pageNumber) {
        return new KeyParameter(applyPageNumber(baseHash, PASSWORD_DIGEST_LENGTH, _pageNumber));
    }

    @Override
    protected int getMaxEncodedPage() {
        return MSISAM_MAX_ENCRYPTED_PAGE;
    }

    private void verifyPassword(ByteBuffer _buffer, byte[] _testEncodingKey, byte[] _testBytes) {
        StreamCipherCompat engine = decryptInit(getStreamCipher(), new KeyParameter(_testEncodingKey));

        byte[] encrypted4BytesCheck = getPasswordTestBytes(_buffer);
        if (isBlankKey(encrypted4BytesCheck)) {
            // no password?
            return;
        }

        byte[] decrypted4BytesCheck = decryptBytes(engine, encrypted4BytesCheck);

        if (!Arrays.equals(decrypted4BytesCheck, _testBytes)) {
            throw new InvalidCredentialsException("Incorrect password provided");
        }
    }

    private static byte[] createPasswordDigest(ByteBuffer _buffer, String _password, Charset _charset) {
        Digest digest = (_buffer.get(ENCRYPTION_FLAGS_OFFSET) & USE_SHA1) != 0 ? new SHA1Digest() : new MD5Digest();

        byte[] passwordBytes = new byte[PASSWORD_LENGTH];

        if (_password != null) {
            ByteBuffer bb = ColumnImpl.encodeUncompressedText(_password.toUpperCase(), _charset);
            bb.get(passwordBytes, 0, Math.min(passwordBytes.length, bb.remaining()));
        }

        // Get digest value
        byte[] digestBytes = hash(digest, passwordBytes, PASSWORD_DIGEST_LENGTH);
        return digestBytes;
    }

    private static byte[] getOldDecryptionKey(ByteBuffer _buffer, JetFormat _format) {
        byte[] encodingKey = ByteUtil.getBytes(_buffer, SALT_OFFSET, JetCryptCodecHandler.ENCODING_KEY_LENGTH);

        // Hash the salt. Step 1.
        final byte[] fullHashData = ByteUtil.getBytes(_buffer, _format.OFFSET_PASSWORD, _format.SIZE_PASSWORD * 2);

        // apply additional mask to header data
        byte[] pwdMask = DatabaseImpl.getPasswordMask(_buffer, _format);
        if (pwdMask != null) {

            for (int i = 0; i < _format.SIZE_PASSWORD; ++i) {
                fullHashData[i] ^= pwdMask[i % pwdMask.length];
            }
            int trailingOffset = fullHashData.length - TRAILING_PWD_LEN;
            for (int i = 0; i < TRAILING_PWD_LEN; ++i) {
                fullHashData[trailingOffset + i] ^= pwdMask[i % pwdMask.length];
            }
        }

        final byte[] hashData = new byte[_format.SIZE_PASSWORD];

        for (int pos = 0; pos < _format.SIZE_PASSWORD; pos++) {
            hashData[pos] = fullHashData[pos * 2];
        }

        hashSalt(encodingKey, hashData);

        // Hash the salt. Step 2
        byte[] jetHeader = ByteUtil.getBytes(_buffer, JetFormat.OFFSET_ENGINE_NAME, JetFormat.LENGTH_ENGINE_NAME);
        hashSalt(encodingKey, jetHeader);

        return encodingKey;
    }

    private static byte[] getPasswordTestBytes(ByteBuffer _buffer) {
        int cryptCheckOffset = ByteUtil.getUnsignedByte(_buffer, SALT_OFFSET);
        return ByteUtil.getBytes(_buffer, CRYPT_CHECK_START + cryptCheckOffset, 4);
    }

    private static void hashSalt(byte[] _salt, byte[] _hashData) {
        ByteBuffer bb = wrap(_salt);

        int hash = bb.getInt();

        for (int pos = 0; pos < _hashData.length; pos++) {
            int tmp = _hashData[pos] & 0xFF;
            tmp <<= pos % 0x18;
            hash ^= tmp;
        }

        bb.rewind();
        bb.putInt(hash);
    }

}
