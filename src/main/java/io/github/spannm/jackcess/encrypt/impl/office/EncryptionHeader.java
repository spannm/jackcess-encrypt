package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.encrypt.InvalidCryptoConfigurationException;
import io.github.spannm.jackcess.impl.ByteUtil;
import io.github.spannm.jackcess.impl.UnsupportedCodecException;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * The EncryptionHeader structure (OC: 2.3.2) found at the start of the encryption info of office
 * encrypted databases.  Describes the crypto and hash algorithm, the key size and the crypto
 * service provider used to encrypt the database.  Instances are usually created via
 * {@link #read(ByteBuffer, Set, Set)}, which additionally validates the header against the
 * algorithms and key sizes supported by the calling provider.
 */
public class EncryptionHeader {
    /** charset used by office encryption for all strings, including passwords */
    public static final Charset UNICODE_CHARSET             = StandardCharsets.UTF_16LE;

    /** header flag indicating CryptoAPI encryption */
    public static final int     FCRYPTO_API_FLAG            = 0x04;
    /** header flag indicating that document properties are encrypted */
    public static final int     FDOC_PROPS_FLAG             = 0x08;
    /** header flag indicating an external (unsupported) crypto provider */
    public static final int     FEXTERNAL_FLAG              = 0x10;
    /** header flag indicating AES encryption */
    public static final int     FAES_FLAG                   = 0x20;

    private static final int    ALGID_FLAGS                 = 0;
    private static final int    ALGID_RC4                   = 0x6801;
    private static final int    ALGID_AES_128               = 0x660E;
    private static final int    ALGID_AES_192               = 0x660F;
    private static final int    ALGID_AES_256               = 0x6610;

    private static final int    HASHALGID_FLAGS             = 0;
    private static final int    HASHALGID_SHA1              = 0x8004;

    private static final String CSP_BASE_STRING             = " base ";
    private static final int    RC4_BASE_DEFAULT_KEY_SIZE   = 0x28;
    private static final int    RC4_STRONG_DEFAULT_KEY_SIZE = 0x80;

    /** the encryption algorithms which may be named by an encryption header */
    public enum CryptoAlgorithm {
        /** externally provided (unsupported) algorithm */
        EXTERNAL(ALGID_FLAGS, 0, 0, 0),
        // the CryptoAPI gives a valid range of 40-128 bits. the CNG spec
        // (http://msdn.microsoft.com/en-us/library/windows/desktop/bb931354%28v=vs.85%29.aspx)
        // gives a range from 8-512 bits. bouncycastle supports 40-2048 bits.
        /** RC4 stream cipher */
        RC4(ALGID_RC4, 20, 0x28, 0x200),
        /** AES with a 128 bit key */
        AES_128(ALGID_AES_128, 32, 0x80, 0x80),
        /** AES with a 192 bit key */
        AES_192(ALGID_AES_192, 32, 0xC0, 0xC0),
        /** AES with a 256 bit key */
        AES_256(ALGID_AES_256, 32, 0x100, 0x100);

        private final int algId;
        private final int encVerifierHashLen;
        private final int keySizeMin;
        private final int keySizeMax;

        CryptoAlgorithm(int _algId, int _encVerifierHashLen, int _keySizeMin, int _keySizeMax) {
            algId = _algId;
            encVerifierHashLen = _encVerifierHashLen;
            keySizeMin = _keySizeMin;
            keySizeMax = _keySizeMax;
        }

        /**
         * @return the algorithm id used in the encryption header
         */
        public int getAlgId() {
            return algId;
        }

        /**
         * @return the smallest key size (in bits) supported by this algorithm, which doubles as the
         *         default key size
         */
        public int getKeySizeMin() {
            return keySizeMin;
        }

        /**
         * @return the length (in bytes) of the encrypted verifier hash of this algorithm
         */
        public int getEncryptedVerifierHashLen() {
            return encVerifierHashLen;
        }

        /**
         * @param _keySize a key size in bits
         * @return {@code true} if the given key size is supported by this algorithm
         */
        public boolean isValidKeySize(int _keySize) {
            return keySizeMin <= _keySize && _keySize <= keySizeMax;
        }
    }

    /** the hash algorithms which may be named by an encryption header */
    public enum HashAlgorithm {
        /** externally provided (unsupported) algorithm */
        EXTERNAL(HASHALGID_FLAGS),
        /** SHA-1 */
        SHA1(HASHALGID_SHA1);

        private final int algId;

        HashAlgorithm(int _algId) {
            algId = _algId;
        }

        /**
         * @return the algorithm id used in the encryption header
         */
        public int getAlgId() {
            return algId;
        }
    }

    private final int             flags;
    private final int             sizeExtra;
    private final CryptoAlgorithm cryptoAlg;
    private final HashAlgorithm   hashAlg;
    private final int             keySize;
    private final int             providerType;
    private final String          cspName;

    /**
     * Reads a header from the given buffer.
     *
     * @param buffer buffer positioned at the start of the EncryptionHeader structure and limited to
     *            its end
     */
    public EncryptionHeader(ByteBuffer buffer) {
        // OC: 2.3.2 EncryptionHeader Structure
        flags = buffer.getInt();
        sizeExtra = buffer.getInt();
        int lalgId = buffer.getInt();
        int lalgIdHash = buffer.getInt();
        int lkeySize = buffer.getInt();
        providerType = buffer.getInt();

        // determine encryption algorithm
        cryptoAlg = parseCryptoAlgorithm(lalgId, flags);

        // determine hash algorithm
        hashAlg = parseHashAlgorithm(lalgIdHash, flags);

        // reserved
        buffer.getInt();
        buffer.getInt();

        cspName = readCspName(buffer);

        keySize = parseKeySize(lkeySize, cryptoAlg, cspName);
    }

    /**
     * @return the header flags, see the {@code F*_FLAG} constants
     */
    public int getFlags() {
        return flags;
    }

    /**
     * @return the size of the extra data of the header (unused, reserved by the specification)
     */
    public int getSizeExtra() {
        return sizeExtra;
    }

    /**
     * @return the encryption algorithm used by the database
     */
    public CryptoAlgorithm getCryptoAlgorithm() {
        return cryptoAlg;
    }

    /**
     * @return the hash algorithm used by the database
     */
    public HashAlgorithm getHashAlgorithm() {
        return hashAlg;
    }

    /**
     * @return the key size in bits, resolved to the algorithm/provider default if the header
     *         contained no explicit size
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * @return the crypto service provider type
     */
    public int getProviderType() {
        return providerType;
    }

    /**
     * @return the name of the crypto service provider, empty if the header contained none
     */
    public String getCspName() {
        return cspName;
    }

    /**
     * Reads the length prefixed header from the given encryption info buffer, verifies it against
     * the given supported algorithms and leaves the buffer positioned after the header.
     *
     * @param encProvBuf buffer positioned at the header length of the encryption info
     * @param validCryptoAlgos the encryption algorithms supported by the caller
     * @param validHashAlgos the hash algorithms supported by the caller
     * @return the header read from the buffer
     * @throws InvalidCryptoConfigurationException if the header names an unsupported algorithm or
     *             an invalid key size
     */
    public static EncryptionHeader read(ByteBuffer encProvBuf, Set<CryptoAlgorithm> validCryptoAlgos, Set<HashAlgorithm> validHashAlgos) {
        // read length of header
        int headerLen = encProvBuf.getInt();

        // read header (temporarily narrowing buf to header)
        int origLimit = encProvBuf.limit();
        int startPos = encProvBuf.position();
        encProvBuf.limit(startPos + headerLen);

        EncryptionHeader header = null;
        try {
            header = new EncryptionHeader(encProvBuf);

            // verify parameters
            if (!validCryptoAlgos.contains(header.getCryptoAlgorithm())) {
                throw new InvalidCryptoConfigurationException(header + " crypto algorithm must be one of " + validCryptoAlgos);
            }

            if (!validHashAlgos.contains(header.getHashAlgorithm())) {
                throw new InvalidCryptoConfigurationException(header + " hash algorithm must be one of " + validHashAlgos);
            }

            int keySz = header.getKeySize();
            if (!header.getCryptoAlgorithm().isValidKeySize(keySz)) {
                throw new InvalidCryptoConfigurationException(header + " key size is outside allowable range");
            }
            if ((keySz % 8) != 0) {
                throw new InvalidCryptoConfigurationException(header + " key size must be multiple of 8");
            }

        } finally {
            // restore original limit
            encProvBuf.limit(origLimit);
        }

        // move to after header
        encProvBuf.position(startPos + headerLen);

        return header;
    }

    private static CryptoAlgorithm parseCryptoAlgorithm(int algId, int flags) {
        switch (algId) {
            case ALGID_FLAGS:
                if (isFlagSet(flags, FEXTERNAL_FLAG)) {
                    return CryptoAlgorithm.EXTERNAL;
                }
                if (isFlagSet(flags, FCRYPTO_API_FLAG)) {
                    return isFlagSet(flags, FAES_FLAG) ? CryptoAlgorithm.AES_128 : CryptoAlgorithm.RC4;
                }
                break;
            case ALGID_RC4:
                return CryptoAlgorithm.RC4;
            case ALGID_AES_128:
                return CryptoAlgorithm.AES_128;
            case ALGID_AES_192:
                return CryptoAlgorithm.AES_192;
            case ALGID_AES_256:
                return CryptoAlgorithm.AES_256;
            default:
                break;
        }

        throw new UnsupportedCodecException("Unsupported encryption algorithm " + algId + " (flags " + flags + ")");
    }

    private static HashAlgorithm parseHashAlgorithm(int algIdHash, int flags) {
        switch (algIdHash) {
            case HASHALGID_FLAGS:
                if (isFlagSet(flags, FEXTERNAL_FLAG)) {
                    return HashAlgorithm.EXTERNAL;
                }
                return HashAlgorithm.SHA1;
            case HASHALGID_SHA1:
                return HashAlgorithm.SHA1;
            default:
                break;
        }

        throw new UnsupportedCodecException("Unsupported hash algorithm " + algIdHash + " (flags " + flags + ")");
    }

    @SuppressWarnings("PMD.ParameterAssignment")
    private static int parseKeySize(int _keySize, CryptoAlgorithm _cryptoAlg, String _cspName) {
        if (_keySize != 0) {
            return _keySize;
        }

        // if keySize is 0, then use algorithm/provider default
        if (_cryptoAlg == CryptoAlgorithm.RC4) {

            // the default key size depends on the crypto service provider. if the
            // provider name was not given, or contains the string " base " use the
            // Base provider default. otherwise, use the Strong provider default.
            // CSPs: http://msdn.microsoft.com/en-us/library/windows/desktop/bb931357%28v=vs.85%29.aspx
            _cspName = _cspName.trim().toLowerCase();
            return _cspName.isEmpty() || _cspName.contains(CSP_BASE_STRING) ? RC4_BASE_DEFAULT_KEY_SIZE : RC4_STRONG_DEFAULT_KEY_SIZE;
        }

        // for all other algorithms, use min key size
        return _cryptoAlg.getKeySizeMin();
    }

    private static String readCspName(ByteBuffer buffer) {

        // unicode string, must be multiple of 2
        int rem = buffer.remaining() / 2 * 2;
        String cspName = "";
        if (rem > 0) {

            ByteBuffer cspNameBuf = ByteBuffer.wrap(ByteUtil.getBytes(buffer, rem));
            CharBuffer tmpCspName = UNICODE_CHARSET.decode(cspNameBuf);

            // should be null terminated, strip that
            for (int i = 0; i < tmpCspName.limit(); ++i) {
                if (tmpCspName.charAt(i) == '\0') {
                    tmpCspName.limit(i);
                    break;
                }
            }

            cspName = tmpCspName.toString();
        }

        return cspName;
    }

    /**
     * @param flagsVal the flags value to test
     * @param flagMask the flag to test for
     * @return {@code true} if the given flag is set
     */
    public static boolean isFlagSet(int flagsVal, int flagMask) {
        return (flagsVal & flagMask) != 0;
    }

    @Override
    public String toString() {
        return String.format("%s[flags=%s, sizeExtra=%s, cryptoAlg=%s, hashAlg=%s, keySize=%s, providerType=%s, cspName=%s]",
            getClass().getSimpleName(), flags, sizeExtra, cryptoAlg, hashAlg, keySize, providerType, cspName);
    }

}
