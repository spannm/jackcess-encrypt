package io.github.spannm.jackcess.encrypt.impl;

import io.github.spannm.jackcess.JackcessRuntimeException;
import io.github.spannm.jackcess.encrypt.InvalidCredentialsException;
import io.github.spannm.jackcess.encrypt.InvalidCryptoConfigurationException;
import io.github.spannm.jackcess.encrypt.impl.office.*;
import io.github.spannm.jackcess.impl.*;
import org.bouncycastle.crypto.Digest;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.function.Supplier;

/**
 * CryptCodecHandler for the  Office Document Cryptography standard.
 */
public abstract class OfficeCryptCodecHandler extends BaseCryptCodecHandler {
    private static final int MAX_PASSWORD_LEN       = 255;
    private static final int CRYPT_STRUCTURE_OFFSET = 0x299;

    protected enum Phase {
        PWD_VERIFY,
        CRYPT;
    }

    private Digest     digest;
    private ByteBuffer tempIntBuf;
    private Phase      phase = Phase.PWD_VERIFY;

    protected OfficeCryptCodecHandler(PageChannel _channel, byte[] _encodingKey) {
        super(_channel, _encodingKey);
    }

    public static CodecHandler create(Supplier<String> _callback, PageChannel _channel, Charset _charset) throws IOException {
        ByteBuffer buffer = readHeaderPage(_channel);
        JetFormat format = _channel.getFormat();

        // the encoding key indicates whether or not the db is encoded (but is
        // otherwise meaningless?)
        byte[] encodingKey = ByteUtil.getBytes(buffer, format.OFFSET_ENCODING_KEY, JetCryptCodecHandler.ENCODING_KEY_LENGTH);

        if (isBlankKey(encodingKey)) {
            return DefaultCodecProvider.DUMMY_HANDLER;
        }

        short infoLen = buffer.getShort(CRYPT_STRUCTURE_OFFSET);

        ByteBuffer encProvBuf = wrap(ByteUtil.getBytes(buffer, CRYPT_STRUCTURE_OFFSET + 2, infoLen));

        // read encoding provider version
        // uint (2.1.4 Version)
        int vMajor = ByteUtil.getUnsignedShort(encProvBuf);
        // uint
        int vMinor = ByteUtil.getUnsignedShort(encProvBuf);

        byte[] pwdBytes = getPasswordBytes(_callback.get());

        OfficeCryptCodecHandler handler = null;
        if ((vMajor == 4) && (vMinor == 4)) {

            // OC: 2.3.4.10 - Agile Encryption: 4,4
            handler = new AgileEncryptionProvider(_channel, encodingKey, encProvBuf, pwdBytes);

        } else if ((vMajor == 1) && (vMinor == 1)) {

            // OC: 2.3.6.1 - RC4 Encryption: 1,1
            handler = new OfficeBinaryDocRC4Provider(_channel, encodingKey, encProvBuf, pwdBytes);

        } else if (((vMajor == 3) || (vMajor == 4)) && (vMinor == 3)) {

            // OC: 2.3.4.6 - Extensible Encryption: (3,4),3

            // since this utilizes arbitrary external providers, we can't really
            // do anything with it
            throw new UnsupportedCodecException("Extensible encryption provider is not supported");

        } else if (((vMajor == 2) || (vMajor == 3) || (vMajor == 4)) && (vMinor == 2)) {

            // read flags (copy of the flags in EncryptionHeader)
            int flags = encProvBuf.getInt();
            if (EncryptionHeader.isFlagSet(flags, EncryptionHeader.FCRYPTO_API_FLAG)) {
                if (EncryptionHeader.isFlagSet(flags, EncryptionHeader.FAES_FLAG)) {
                    // OC: 2.3.4.5 - Standard Encryption: (3,4),2
                    handler = new ECMAStandardEncryptionProvider(_channel, encodingKey, encProvBuf, pwdBytes);
                } else {

                    int initPos = encProvBuf.position();
                    try {

                        // OC: 2.3.5.1 - RC4 CryptoAPI Encryption: (2,3,4),2
                        handler = new RC4CryptoAPIProvider(_channel, encodingKey, encProvBuf, pwdBytes);

                    } catch (InvalidCryptoConfigurationException _ex) {

                        // is this the "non-standard" encryption provider?
                        try {
                            // reset encryption info buf before attempting to re-process
                            encProvBuf.position(initPos);
                            handler = new NonStandardEncryptionProvider(_channel, encodingKey, encProvBuf, pwdBytes);
                        } catch (Exception _ignored) {
                            // ignore nested exception, continue with original
                            throw _ex;
                        }
                    }
                }
            }
        }

        if (handler == null) {
            throw new UnsupportedCodecException("Unsupported office encryption provider: vMajor " + vMajor + ", vMinor " + vMinor);
        }

        if (!handler.verifyPassword(pwdBytes)) {
            throw new InvalidCredentialsException("Incorrect password provided");
        }

        handler.reset();
        handler.phase = Phase.CRYPT;

        return handler;
    }

    protected Phase getPhase() {
        return phase;
    }

    protected Digest getDigest() {
        if (digest == null) {
            digest = initDigest();
        }
        return digest;
    }

    protected Digest initDigest() {
        switch (getPhase()) {
            case PWD_VERIFY:
                return initPwdDigest();
            case CRYPT:
                return initCryptDigest();
            default:
                throw new JackcessRuntimeException("Unknown phase " + getPhase());
        }
    }

    protected Digest initPwdDigest() {
        throw new UnsupportedOperationException();
    }

    protected Digest initCryptDigest() {
        throw new UnsupportedOperationException();
    }

    protected final byte[] int2bytes(int _val) {
        if (tempIntBuf == null) {
            tempIntBuf = wrap(new byte[4]);
        }
        tempIntBuf.putInt(0, _val);
        return tempIntBuf.array();
    }

    protected void reset() {
        digest = null;
    }

    @Override
    public void decodePage(ByteBuffer _inPage, ByteBuffer _outPage, int _pageNumber) {
        if (!isEncryptedPage(_pageNumber)) {
            // not encoded
            return;
        }

        decodePageImpl(_inPage, _outPage, _pageNumber);
    }

    @Override
    public ByteBuffer encodePage(ByteBuffer _buffer, int _pageNumber, int _pageOffset) {
        if (!isEncryptedPage(_pageNumber)) {
            // not encoded
            return _buffer;
        }

        return encodePageImpl(_buffer, _pageNumber, _pageOffset);
    }

    protected byte[] iterateHash(byte[] _baseHash, int _iterations) {
        if (_iterations == 0) {
            return _baseHash;
        }

        Digest ldigest = getDigest();
        byte[] literHash = _baseHash;
        for (int i = 0; i < _iterations; ++i) {
            literHash = hash(ldigest, int2bytes(i), literHash);
        }
        return literHash;
    }

    private static boolean isEncryptedPage(int _pageNumber) {
        return _pageNumber > 0;
    }

    @SuppressWarnings("PMD.ParameterAssignment")
    private static byte[] getPasswordBytes(String _password) {
        if (_password == null) {
            return new byte[0];
        }
        if (_password.length() > MAX_PASSWORD_LEN) {
            _password = _password.substring(0, MAX_PASSWORD_LEN);
        }

        return _password.getBytes(EncryptionHeader.UNICODE_CHARSET);
    }

    protected static int bits2bytes(int _bits) {
        return _bits / 8;
    }

    protected abstract void decodePageImpl(ByteBuffer _inPage, ByteBuffer _outPage, int _pageNumber);

    protected abstract ByteBuffer encodePageImpl(ByteBuffer _buffer, int _pageNumber, int _pageOffset);

    protected abstract boolean verifyPassword(byte[] _password);

}
