package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.impl.PageChannel;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * The "non-standard" provider handles the case where AES is enabled for older
 * databases with the office crypto "compatmode" set to 0 (non-compatible).
 * <br>
 * More details <a href="https://sourceforge.net/p/jackcessencrypt/bugs/6/">here</a>.
 */
public class NonStandardEncryptionProvider extends ECMAStandardEncryptionProvider {
    private static final int HASH_ITERATIONS = 0;

    /**
     * Creates a new provider reading its configuration from the given encryption info buffer.
     *
     * @param _channel the page channel of the database being opened
     * @param _encodingKey the encoding key read from the database header
     * @param _encProvBuf buffer positioned at the encryption provider info
     * @param _password the password bytes (UTF-16LE encoded)
     * @throws IOException if the encryption info could not be read
     */
    public NonStandardEncryptionProvider(PageChannel _channel, byte[] _encodingKey, ByteBuffer _encProvBuf, byte[] _password) throws IOException {
        super(_channel, _encodingKey, _encProvBuf, _password, HASH_ITERATIONS);
    }
}
