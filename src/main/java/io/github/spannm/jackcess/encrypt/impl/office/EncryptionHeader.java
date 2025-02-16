package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.encrypt.InvalidCryptoConfigurationException;
import io.github.spannm.jackcess.impl.ByteUtil;
import io.github.spannm.jackcess.impl.UnsupportedCodecException;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Set;

public class EncryptionHeader {
    public static final Charset UNICODE_CHARSET             = StandardCharsets.UTF_16LE;

    public static final int     FCRYPTO_API_FLAG            = 0x04;
    public static final int     FDOC_PROPS_FLAG             = 0x08;
    public static final int     FEXTERNAL_FLAG              = 0x10;
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

    public enum CryptoAlgorithm {
        EXTERNAL(ALGID_FLAGS, 0, 0, 0),
        // the CryptoAPI gives a valid range of 40-128 bits. the CNG spec
        // (http://msdn.microsoft.com/en-us/library/windows/desktop/bb931354%28v=vs.85%29.aspx)
        // gives a range from 8-512 bits. bouncycastle supports 40-2048 bits.
        RC4(ALGID_RC4, 20, 0x28, 0x200),
        AES_128(ALGID_AES_128, 32, 0x80, 0x80),
        AES_192(ALGID_AES_192, 32, 0xC0, 0xC0),
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

        public int getAlgId() {
            return algId;
        }

        public int getKeySizeMin() {
            return keySizeMin;
        }

        public int getEncryptedVerifierHashLen() {
            return encVerifierHashLen;
        }

        public boolean isValidKeySize(int _keySize) {
            return keySizeMin <= _keySize && _keySize <= keySizeMax;
        }
    }

    public enum HashAlgorithm {
        EXTERNAL(HASHALGID_FLAGS),
        SHA1(HASHALGID_SHA1);

        private final int algId;

        HashAlgorithm(int _algId) {
            algId = _algId;
        }

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

    public int getFlags() {
        return flags;
    }

    public int getSizeExtra() {
        return sizeExtra;
    }

    public CryptoAlgorithm getCryptoAlgorithm() {
        return cryptoAlg;
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlg;
    }

    public int getKeySize() {
        return keySize;
    }

    public int getProviderType() {
        return providerType;
    }

    public String getCspName() {
        return cspName;
    }

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
            return _cspName.length() == 0 || _cspName.contains(CSP_BASE_STRING) ? RC4_BASE_DEFAULT_KEY_SIZE : RC4_STRONG_DEFAULT_KEY_SIZE;
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

    public static boolean isFlagSet(int flagsVal, int flagMask) {
        return (flagsVal & flagMask) != 0;
    }

    @Override
    public String toString() {
        return String.format("%s[flags=%s, sizeExtra=%s, cryptoAlg=%s, hashAlg=%s, keySize=%s, providerType=%s, cspName=%s]",
            getClass().getSimpleName(), flags, sizeExtra, cryptoAlg, hashAlg, keySize, providerType, cspName);
    }

}
