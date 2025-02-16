package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.encrypt.impl.OfficeCryptCodecHandler;
import io.github.spannm.jackcess.encrypt.util.StreamCipherCompat;
import io.github.spannm.jackcess.impl.PageChannel;

import java.nio.ByteBuffer;

public abstract class StreamCipherProvider extends OfficeCryptCodecHandler {
    private StreamCipherCompat cipher;

    protected StreamCipherProvider(PageChannel _channel, byte[] _encodingKey) {
        super(_channel, _encodingKey);
    }

    @Override
    public boolean canDecodeInline() {
        // stream ciphers can decode on top of the input buffer
        return true;
    }

    @Override
    protected StreamCipherCompat getStreamCipher() {
        if (cipher == null) {
            cipher = initCipher();
        }
        return cipher;
    }

    protected StreamCipherCompat initCipher() {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void decodePageImpl(ByteBuffer _inPage, ByteBuffer _outPage, int _pageNumber) {
        streamDecrypt(_inPage, _pageNumber);
    }

    @Override
    public ByteBuffer encodePageImpl(ByteBuffer _buffer, int _pageNumber, int _pageOffset) {
        return streamEncrypt(_buffer, _pageNumber, _pageOffset);
    }

    @Override
    protected void reset() {
        super.reset();
        cipher = null;
    }
}
