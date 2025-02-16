package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.JackcessRuntimeException;
import io.github.spannm.jackcess.encrypt.impl.OfficeCryptCodecHandler;
import io.github.spannm.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;

import java.nio.ByteBuffer;

public abstract class BlockCipherProvider extends OfficeCryptCodecHandler {
    private BufferedBlockCipher cipher;

    public BlockCipherProvider(PageChannel _channel, byte[] _encodingKey) {
        super(_channel, _encodingKey);
    }

    @Override
    @SuppressWarnings("deprecation")
    protected BufferedBlockCipher getBlockCipher() {
        if (cipher == null) {
            cipher = new BufferedBlockCipher(initCipher());
        }
        return cipher;
    }

    @Override
    public final boolean canEncodePartialPage() {
        // for a variety of reasons, it's difficult (or impossible if chaining
        // modes are in use) for block ciphers to encode partial pages.
        return false;
    }

    @Override
    public final boolean canDecodeInline() {
        // block ciphers cannot decode on top of the input buffer
        return false;
    }

    protected BlockCipher initCipher() {
        switch (getPhase()) {
            case PWD_VERIFY:
                return initPwdCipher();
            case CRYPT:
                return initCryptCipher();
            default:
                throw new JackcessRuntimeException("Unknown phase " + getPhase());
        }
    }

    protected BlockCipher initPwdCipher() {
        throw new UnsupportedOperationException();
    }

    protected BlockCipher initCryptCipher() {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void decodePageImpl(ByteBuffer _inPage, ByteBuffer _outPage, int _pageNumber) {
        blockDecrypt(_inPage, _outPage, _pageNumber);
    }

    @Override
    public ByteBuffer encodePageImpl(ByteBuffer _buffer, int _pageNumber, int _pageOffset) {
        return blockEncrypt(_buffer, _pageNumber);
    }

    @Override
    protected void reset() {
        super.reset();
        cipher = null;
    }
}
