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
 * CryptCodecHandler for the Office Document Cryptography standard (MS-OFFCRYPTO), used by newer
 * Access database files.  Reads the encryption provider version from the database header and
 * delegates to the matching provider implementation in
 * {@link io.github.spannm.jackcess.encrypt.impl.office} (agile, ECMA-376 standard, RC4 CryptoAPI or
 * binary document RC4 encryption).
 * <p>
 * A handler runs through two phases: while the password is being verified the
 * {@link Phase#PWD_VERIFY} digest/cipher configuration is used, afterwards the handler is reset to
 * the {@link Phase#CRYPT} configuration used for actual page encryption and decryption.  For most
 * schemes both phases use the same algorithms; agile encryption is the notable exception.
 */
public abstract class OfficeCryptCodecHandler extends BaseCryptCodecHandler {
    private static final int MAX_PASSWORD_LEN       = 255;
    private static final int CRYPT_STRUCTURE_OFFSET = 0x299;

    /** the phases a handler runs through, each of which may use a different digest/cipher */
    protected enum Phase {
        /** initial phase, during which the given password is verified */
        PWD_VERIFY,
        /** normal phase, during which database pages are encrypted and decrypted */
        CRYPT
    }

    private Digest     digest;
    private ByteBuffer tempIntBuf;
    private Phase      phase = Phase.PWD_VERIFY;

    /**
     * Creates a new handler for the given page channel.
     *
     * @param _channel the page channel of the database being read or written
     * @param _encodingKey the encoding key read from the database header
     */
    protected OfficeCryptCodecHandler(PageChannel _channel, byte[] _encodingKey) {
        super(_channel, _encodingKey);
    }

    /**
     * Creates a handler for the given office encrypted database.  Determines the encryption
     * provider from the header, verifies the password (retrieved from the given supplier only if
     * the database is actually encoded) and returns the fully initialized handler.
     *
     * @param _callback supplier invoked if a password is required
     * @param _channel the page channel of the database being opened
     * @param _charset the charset of the database being opened, currently unused as office
     *            encryption always encodes passwords as UTF-16LE
     * @return a handler for the database, or the dummy (no-op) handler if the database turns out to
     *         be unencoded
     * @throws IOException if the database header could not be read
     * @throws io.github.spannm.jackcess.impl.UnsupportedCodecException if the database uses an
     *             encryption provider which is not supported
     * @throws InvalidCredentialsException if the given password is not correct
     * @throws InvalidCryptoConfigurationException if the crypto configuration of the database is
     *             invalid
     */
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

    /**
     * @return the phase this handler is currently in
     */
    protected Phase getPhase() {
        return phase;
    }

    /**
     * Returns the (lazily created) digest for the current phase.
     *
     * @return the digest to use
     */
    protected final Digest getDigest() {
        if (digest == null) {
            digest = initDigest();
        }
        return digest;
    }

    /**
     * Creates the digest matching the current phase.
     *
     * @return a new digest instance
     */
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

    /**
     * Creates the digest used while verifying the password.
     *
     * @return a new digest instance
     * @throws UnsupportedOperationException if this handler does not use a phase specific digest
     */
    protected Digest initPwdDigest() {
        throw new UnsupportedOperationException();
    }

    /**
     * Creates the digest used while encrypting and decrypting pages.
     *
     * @return a new digest instance
     * @throws UnsupportedOperationException if this handler does not use a phase specific digest
     */
    protected Digest initCryptDigest() {
        throw new UnsupportedOperationException();
    }

    /**
     * Converts the given int into a 4 byte array using the database byte order.  Note, the returned
     * array is a shared scratch buffer which is overwritten by the next invocation.
     *
     * @param _val the value to convert
     * @return the bytes of the given value
     */
    protected final byte[] int2bytes(int _val) {
        if (tempIntBuf == null) {
            tempIntBuf = wrap(new byte[4]);
        }
        tempIntBuf.putInt(0, _val);
        return tempIntBuf.array();
    }

    /**
     * Discards the cached, phase dependent crypto state so that it is recreated on next use.
     */
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

    /**
     * Iteratively hashes the given base hash, prefixing each round with the round number.
     *
     * @param _baseHash the initial hash value
     * @param _iterations the number of rounds, {@code 0} to return the base hash unchanged
     * @return the resulting hash value
     */
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

    /**
     * @param _bits a number of bits
     * @return the corresponding number of bytes
     */
    protected static int bits2bytes(int _bits) {
        return _bits / 8;
    }

    /**
     * Decrypts the given page, which has been determined to be encrypted.
     *
     * @param _inPage the buffer holding the encrypted page
     * @param _outPage the buffer receiving the decrypted page
     * @param _pageNumber the number of the page contained in the buffer
     */
    protected abstract void decodePageImpl(ByteBuffer _inPage, ByteBuffer _outPage, int _pageNumber);

    /**
     * Encrypts the given page, which has been determined to require encryption.
     *
     * @param _buffer the page buffer to encrypt
     * @param _pageNumber the number of the page contained in the buffer
     * @param _pageOffset the offset within the page at which the modified data starts
     * @return a buffer holding the encrypted page
     */
    protected abstract ByteBuffer encodePageImpl(ByteBuffer _buffer, int _pageNumber, int _pageOffset);

    /**
     * Verifies the given password against the verifier information of the database.
     *
     * @param _password the password bytes (UTF-16LE encoded)
     * @return {@code true} if the password is correct, {@code false} otherwise
     */
    protected abstract boolean verifyPassword(byte[] _password);

}
