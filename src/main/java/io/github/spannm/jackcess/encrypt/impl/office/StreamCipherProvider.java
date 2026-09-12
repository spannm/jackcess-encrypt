package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.encrypt.impl.OfficeCryptCodecHandler;
import io.github.spannm.jackcess.encrypt.util.StreamCipherCompat;
import io.github.spannm.jackcess.impl.PageChannel;

import java.nio.ByteBuffer;

/**
 * Base class for office encryption providers which use a stream cipher (RC4).  Manages the lazily
 * created cipher instance and implements page encoding/decoding on top of it.  Subclasses supply
 * the actual cipher by overriding {@link #initCipher()}.  In contrast to
 * {@link BlockCipherProvider}, stream ciphers can decode on top of the input buffer.
 */
public abstract class StreamCipherProvider extends OfficeCryptCodecHandler {
    private StreamCipherCompat cipher;

    /**
     * Creates a new provider for the given page channel.
     *
     * @param _channel the page channel of the database being read or written
     * @param _encodingKey the encoding key read from the database header
     */
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

    /**
     * Creates the stream cipher used by this provider.
     *
     * @return a new stream cipher instance
     * @throws UnsupportedOperationException if the subclass does not provide a cipher
     */
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
