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

    public NonStandardEncryptionProvider(PageChannel _channel, byte[] _encodingKey, ByteBuffer _encProvBuf, byte[] _password) throws IOException {
        super(_channel, _encodingKey, _encProvBuf, _password, HASH_ITERATIONS);
    }
}
