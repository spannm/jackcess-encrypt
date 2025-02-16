package io.github.spannm.jackcess.encrypt.impl;

import io.github.spannm.jackcess.encrypt.util.StreamCipherCompat;
import io.github.spannm.jackcess.encrypt.util.StreamCipherFactory;
import io.github.spannm.jackcess.impl.PageChannel;

import java.nio.ByteBuffer;

/**
 * Base CodecHandler support for Jet RC4 encryption based CodecHandlers.
 */
public abstract class BaseJetCryptCodecHandler extends BaseCryptCodecHandler {
    private StreamCipherCompat engine;

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

    protected abstract int getMaxEncodedPage();
}
