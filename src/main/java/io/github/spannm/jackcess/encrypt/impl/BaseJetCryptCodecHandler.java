package io.github.spannm.jackcess.encrypt.impl;

import io.github.spannm.jackcess.encrypt.util.StreamCipherCompat;
import io.github.spannm.jackcess.encrypt.util.StreamCipherFactory;
import io.github.spannm.jackcess.impl.PageChannel;

import java.nio.ByteBuffer;

/**
 * Base CodecHandler support for Jet RC4 encryption based CodecHandlers.  Handles page
 * encoding/decoding with a lazily created RC4 engine and skips pages outside the encrypted page
 * range reported by {@link #getMaxEncodedPage()}.
 */
public abstract class BaseJetCryptCodecHandler extends BaseCryptCodecHandler {
    private StreamCipherCompat engine;

    /**
     * Creates a new handler for the given page channel.
     *
     * @param _channel the page channel of the database being read or written
     * @param _encodingKey the database specific encoding key, may be {@code null}
     */
    protected BaseJetCryptCodecHandler(PageChannel _channel, byte[] _encodingKey) {
        super(_channel, _encodingKey);
    }

    @Override
    public boolean canEncodePartialPage() {
        // RC4 ciphers are not influenced by the page contents, so we can easily
        // encode part of the buffer.
        return true;
    }

    @Override
    public boolean canDecodeInline() {
        // RC4 ciphers can decode on top of the input buffer
        return true;
    }

    @Override
    protected final StreamCipherCompat getStreamCipher() {
        if (engine == null) {
            engine = StreamCipherFactory.newRC4Engine();
        }
        return engine;
    }

    @Override
    public void decodePage(ByteBuffer _inPage, ByteBuffer _outPage, int _pageNumber) {
        if (!isEncryptedPage(_pageNumber)) {
            // not encoded
            return;
        }

        streamDecrypt(_inPage, _pageNumber);
    }

    @Override
    public ByteBuffer encodePage(ByteBuffer _buffer, int _pageNumber, int _pageOffset) {
        if (!isEncryptedPage(_pageNumber)) {
            // not encoded
            return _buffer;
        }

        return streamEncrypt(_buffer, _pageNumber, _pageOffset);
    }

    private boolean isEncryptedPage(int _pageNumber) {
        return _pageNumber > 0 && _pageNumber <= getMaxEncodedPage();
    }

    /**
     * Returns the number of the last encrypted page.  Pages beyond this number (and the header
     * page 0) are stored unencrypted.
     *
     * @return the highest page number which is encrypted
     */
    protected abstract int getMaxEncodedPage();
}
