package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.encrypt.InvalidCryptoConfigurationException;
import io.github.spannm.jackcess.encrypt.model.CTEncryption;
import io.github.spannm.jackcess.encrypt.util.StreamCipherCompat;
import io.github.spannm.jackcess.encrypt.util.StreamCipherFactory;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Utility for working with the xml encryption descriptor of agile encryption (OC: 2.3.4.10).
 * Parsing is delegated to {@link XmlEncryptionParser}; this class additionally maps the algorithm
 * names used in the descriptor onto the matching bouncycastle digests, block ciphers and chaining
 * modes.  Where bouncycastle offers no direct equivalent (RC4 as a "block" cipher, ECB and AEAD
 * chaining modes), thin adapter implementations are provided here.
 */
@SuppressWarnings("deprecation")
public final class XmlEncryptionDescriptor {
    // this value doesn't matter, just multiple of 2
    private static final int STREAM_CIPHER_BLOCK_SIZE = 16;

    /** the cipher algorithms which may be named by an xml encryption descriptor */
    public enum CipherAlgorithm {
        /** AES */
        AES(AESEngine.class),
        /** RC2 */
        RC2(RC2Engine.class),
        /** RC4, adapted to the block cipher api */
        RC4(RC4BlockCipher.class),
        /** DES */
        DES(DESEngine.class),
        // DESX,
        /** triple DES */
        _3DES(DESedeEngine.class),
        /** triple DES with a 112 bit key */
        _3DES112(DESedeEngine.class);

        private final Class<? extends BlockCipher> blockCipherClazz;

        CipherAlgorithm(Class<? extends BlockCipher> _blockCipherClazz) {
            blockCipherClazz = _blockCipherClazz;
        }

        /**
         * @return a new, uninitialized cipher instance for this algorithm
         */
        public BlockCipher initBlockCipher() {
            return newInstance(blockCipherClazz);
        }
    }

    /** the cipher chaining modes which may be named by an xml encryption descriptor */
    public enum CipherChaining {
        /** cipher block chaining */
        CHAININGMODECBC {
            @Override
            public BlockCipher initChainingMode(BlockCipher _baseCipher) {
                return new CBCBlockCipher(_baseCipher);
            }
        },
        /** cipher feedback */
        CHAININGMODECFB {
            @Override
            public BlockCipher initChainingMode(BlockCipher _baseCipher) {
                return new CFBBlockCipher(_baseCipher, 8);
            }
        },
        /** counter with CBC-MAC */
        CHAININGMODECCM {
            @Override
            public BlockCipher initChainingMode(BlockCipher _baseCipher) {
                return new AEADBlockCipherAdapter(new CCMBlockCipher(_baseCipher));
            }
        },
        /** Galois/counter mode */
        CHAININGMODEGCM {
            @Override
            public BlockCipher initChainingMode(BlockCipher _baseCipher) {
                return new AEADBlockCipherAdapter(new GCMBlockCipher(_baseCipher));
            }
        },
        /** electronic codebook (no chaining) */
        CHAININGMODEECB {
            @Override
            public BlockCipher initChainingMode(BlockCipher _baseCipher) {
                return new ECBBlockCipher(_baseCipher);
            }
        };

        /**
         * Wraps the given cipher in this chaining mode.
         *
         * @param _baseCipher the base cipher
         * @return the cipher with the chaining mode applied
         */
        public abstract BlockCipher initChainingMode(BlockCipher _baseCipher);
    }

    /** the hash algorithms which may be named by an xml encryption descriptor */
    public enum HashAlgorithm {
        /** SHA-1 */
        SHA1(SHA1Digest.class),
        /** SHA-256 */
        SHA256(SHA256Digest.class),
        /** SHA-384 */
        SHA384(SHA384Digest.class),
        /** SHA-512 */
        SHA512(SHA512Digest.class),
        /** MD5 */
        MD5(MD5Digest.class),
        /** MD4 */
        MD4(MD4Digest.class),
        /** MD2 */
        MD2(MD2Digest.class),
        /** RIPEMD-128 */
        RIPEMD128(RIPEMD128Digest.class),
        /** RIPEMD-160 */
        RIPEMD160(RIPEMD160Digest.class),
        /** Whirlpool */
        WHIRLPOOL(WhirlpoolDigest.class);

        private final Class<? extends Digest> digestClazz;

        HashAlgorithm(Class<? extends Digest> _digestClazz) {
            digestClazz = _digestClazz;
        }

        /**
         * @return a new digest instance for this algorithm
         */
        public Digest initDigest() {
            return newInstance(digestClazz);
        }
    }

    private XmlEncryptionDescriptor() {
    }

    /**
     * Parses the given xml encryption descriptor.
     *
     * @param _xmlBytes the raw xml bytes taken from the database header
     * @return the parsed encryption descriptor
     * @throws InvalidCryptoConfigurationException if the descriptor could not be parsed
     */
    public static CTEncryption parseEncryptionDescriptor(byte[] _xmlBytes) {
        return XmlEncryptionParser.parseEncryptionDescriptor(_xmlBytes);
    }

    private static CipherAlgorithm getAlgorithm(String _str) {
        return parseEnum(_str, CipherAlgorithm.class);
    }

    private static CipherChaining getChaining(String str) {
        return parseEnum(str, CipherChaining.class);
    }

    private static HashAlgorithm getHash(String str) {
        return parseEnum(str, HashAlgorithm.class);
    }

    /**
     * Creates the digest named by the given descriptor value.
     *
     * @param str the hash algorithm name as found in the encryption descriptor
     * @return a new digest instance
     * @throws InvalidCryptoConfigurationException if the algorithm is not supported
     */
    public static Digest initDigest(String str) {
        return getHash(str).initDigest();
    }

    /**
     * Creates the cipher named by the given descriptor values.
     *
     * @param _cipherStr the cipher algorithm name as found in the encryption descriptor
     * @param _chainStr the cipher chaining name as found in the encryption descriptor
     * @return a new cipher instance with the chaining mode applied
     * @throws InvalidCryptoConfigurationException if the algorithm or chaining mode is not
     *             supported
     */
    public static BlockCipher initCipher(String _cipherStr, String _chainStr) {
        return getChaining(_chainStr).initChainingMode(getAlgorithm(_cipherStr).initBlockCipher());
    }

    @SuppressWarnings("PMD.ParameterAssignment")
    private static <E extends Enum<E>> E parseEnum(String _str, Class<E> _enumClazz) {
        String origStr = _str;
        // massage the enum str a bit to be a valid enum
        _str = _str.trim().toUpperCase().replaceAll("[-_]", "");
        if ((!_str.isEmpty()) && Character.isDigit(_str.charAt(0))) {
            _str = '_' + _str;
        }
        try {
            return Enum.valueOf(_enumClazz, _str);
        } catch (IllegalArgumentException _ex) {
            throw new InvalidCryptoConfigurationException("Unsupported encryption parameter: " + origStr);
        }
    }

    private static <T> T newInstance(Class<? extends T> _clazz) {
        try {
            return _clazz.getDeclaredConstructor().newInstance();
        } catch (Exception _ex) {
            throw new InvalidCryptoConfigurationException("Failed initializing encryption algorithm: " + _clazz.getSimpleName(), _ex);
        }
    }

    private static final class AEADBlockCipherAdapter implements BlockCipher {
        private final AEADBlockCipher cipher;

        private AEADBlockCipherAdapter(AEADBlockCipher _cipher) {
            cipher = _cipher;
        }

        @Override
        public String getAlgorithmName() {
            return cipher.getAlgorithmName();
        }

        @Override
        public int getBlockSize() {
            return cipher.getUnderlyingCipher().getBlockSize();
        }

        @Override
        public void init(boolean _forEncryption, CipherParameters _params) {
            cipher.init(_forEncryption, _params);
        }

        @Override
        public int processBlock(byte[] _in, int _inOff, byte[] _out, int _outOff) {
            return cipher.processBytes(_in, _inOff, getBlockSize(), _out, _outOff);
        }

        @Override
        public void reset() {
            cipher.reset();
        }
    }

    private static final class ECBBlockCipher implements BlockCipher {
        private final BlockCipher cipher;

        private ECBBlockCipher(BlockCipher _cipher) {
            cipher = _cipher;
        }

        @Override
        public String getAlgorithmName() {
            return cipher.getAlgorithmName();
        }

        @Override
        public int getBlockSize() {
            return cipher.getBlockSize();
        }

        @Override
        public void init(boolean _forEncryption, CipherParameters _params) {
            if (_params instanceof ParametersWithIV) {
                cipher.init(_forEncryption, ((ParametersWithIV) _params).getParameters());
            } else if (_params instanceof KeyParameter) {
                cipher.init(_forEncryption, _params);
            } else {
                throw new IllegalArgumentException("invalid parameters passed to ECB");
            }
        }

        @Override
        public int processBlock(byte[] _in, int _inOff, byte[] _out, int _outOff) {
            return cipher.processBlock(_in, _inOff, _out, _outOff);
        }

        @Override
        public void reset() {
            cipher.reset();
        }
    }

    private static class BlockCipherAdapter implements BlockCipher {
        private final StreamCipherCompat cipher;

        private BlockCipherAdapter(StreamCipherCompat _cipher) {
            cipher = _cipher;
        }

        @Override
        public String getAlgorithmName() {
            return cipher.getAlgorithmName();
        }

        @Override
        public int getBlockSize() {
            return STREAM_CIPHER_BLOCK_SIZE;
        }

        @Override
        public void init(boolean _forEncryption, CipherParameters _params) {
            if (_params instanceof ParametersWithIV) {
                cipher.init(_forEncryption, ((ParametersWithIV) _params).getParameters());
            } else if (_params instanceof KeyParameter) {
                cipher.init(_forEncryption, _params);
            } else {
                throw new IllegalArgumentException("invalid parameters passed to " + getAlgorithmName());
            }
        }

        @Override
        public int processBlock(byte[] _in, int _inOff, byte[] _out, int _outOff) {
            cipher.processStreamBytes(_in, _inOff, STREAM_CIPHER_BLOCK_SIZE, _out, _outOff);
            return STREAM_CIPHER_BLOCK_SIZE;
        }

        @Override
        public void reset() {
            cipher.reset();
        }
    }

    /** an RC4 engine exposed through the bouncycastle block cipher api */
    public static final class RC4BlockCipher extends BlockCipherAdapter {
        /**
         * Creates a new RC4 cipher.
         */
        public RC4BlockCipher() {
            super(StreamCipherFactory.newRC4Engine());
        }
    }

}
