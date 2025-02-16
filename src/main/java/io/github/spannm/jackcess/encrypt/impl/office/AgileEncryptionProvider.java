package io.github.spannm.jackcess.encrypt.impl.office;

import io.github.spannm.jackcess.encrypt.InvalidCryptoConfigurationException;
import io.github.spannm.jackcess.encrypt.model.CTEncryption;
import io.github.spannm.jackcess.encrypt.model.CTKeyData;
import io.github.spannm.jackcess.encrypt.model.CTKeyEncryptor;
import io.github.spannm.jackcess.encrypt.model.password.CTPasswordKeyEncryptor;
import io.github.spannm.jackcess.encrypt.model.password.STPasswordKeyEncryptorUri;
import io.github.spannm.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class AgileEncryptionProvider extends BlockCipherProvider {
    private static final int             RESERVED_VAL             = 0x40;
    private static final byte[]          ENC_VERIFIER_INPUT_BLOCK = {(byte) 0xfe, (byte) 0xa7, (byte) 0xd2, (byte) 0x76, (byte) 0x3b, (byte) 0x4b, (byte) 0x9e, (byte) 0x79};
    private static final byte[]          ENC_VERIFIER_VALUE_BLOCK = {(byte) 0xd7, (byte) 0xaa, (byte) 0x0f, (byte) 0x6d, (byte) 0x30, (byte) 0x61, (byte) 0x34, (byte) 0x4e};
    private static final byte[]          ENC_VALUE_BLOCK          = {(byte) 0x14, (byte) 0x6e, (byte) 0x0b, (byte) 0xe7, (byte) 0xab, (byte) 0xac, (byte) 0xd0, (byte) 0xd6};

    private final CTEncryption           encryptDesc;
    private final CTPasswordKeyEncryptor pwdKeyEnc;
    private final byte[]                 keyValue;

    public AgileEncryptionProvider(PageChannel _channel, byte[] _encodingKey, ByteBuffer _encProvBuf, byte[] _password) throws IOException {
        super(_channel, _encodingKey);

        // OC: 2.3.4.10
        int reservedVal = _encProvBuf.getInt();
        if (reservedVal != RESERVED_VAL) {
            throw new InvalidCryptoConfigurationException("Unexpected reserved value " + reservedVal);
        }

        byte[] xmlBytes = new byte[_encProvBuf.remaining()];
        _encProvBuf.get(xmlBytes);
        encryptDesc = XmlEncryptionDescriptor.parseEncryptionDescriptor(xmlBytes);

        // for now we expect a single, password key encryptor
        CTPasswordKeyEncryptor lpwdKeyEnc = null;
        if ((encryptDesc.getKeyEncryptors() != null) && (encryptDesc.getKeyEncryptors().getKeyEncryptor().size() == 1)) {
            CTKeyEncryptor keyEnc = encryptDesc.getKeyEncryptors().getKeyEncryptor().get(0);
            if (STPasswordKeyEncryptorUri.HTTP_SCHEMAS_MICROSOFT_COM_OFFICE_2006_KEY_ENCRYPTOR_PASSWORD.value().equals(keyEnc.getUri())) {
                lpwdKeyEnc = (CTPasswordKeyEncryptor) keyEnc.getAny();
            }
        }

        if (lpwdKeyEnc == null) {
            throw new InvalidCryptoConfigurationException("Missing or unexpected key encryptor");
        }
        pwdKeyEnc = lpwdKeyEnc;

        keyValue = decryptKeyValue(_password);
    }

    @Override
    protected Digest initPwdDigest() {
        return XmlEncryptionDescriptor.initDigest(pwdKeyEnc.getHashAlgorithm());
    }

    @Override
    protected Digest initCryptDigest() {
        return XmlEncryptionDescriptor.initDigest(encryptDesc.getKeyData().getHashAlgorithm());
    }

    @Override
    protected BlockCipher initPwdCipher() {
        return XmlEncryptionDescriptor.initCipher(pwdKeyEnc.getCipherAlgorithm(), pwdKeyEnc.getCipherChaining());
    }

    @Override
    protected BlockCipher initCryptCipher() {
        CTKeyData keyData = encryptDesc.getKeyData();
        return XmlEncryptionDescriptor.initCipher(keyData.getCipherAlgorithm(), keyData.getCipherChaining());
    }

    @Override
    protected boolean verifyPassword(byte[] _pwdBytes) {

        byte[] verifier = decryptVerifierHashInput(_pwdBytes);
        byte[] verifierHash = decryptVerifierHashValue(_pwdBytes);

        byte[] testHash = hash(getDigest(), verifier);
        int blockSize = (int) pwdKeyEnc.getBlockSize();
        // hash length needs to be rounded up to nearest blockSize
        if ((testHash.length % blockSize) != 0) {
            int hashLen = (testHash.length + blockSize - 1) / blockSize * blockSize;
            testHash = fixToLength(testHash, hashLen);
        }

        return Arrays.equals(verifierHash, testHash);
    }

    @Override
    protected ParametersWithIV computeCipherParams(int _pageNumber) {
        // when actually decrypting pages, we incorporate the "encoding key"
        byte[] blockBytes = getEncodingKey(_pageNumber);

        CTKeyData keyData = encryptDesc.getKeyData();
        byte[] iv = cryptDeriveIV(blockBytes, keyData.getSaltValue(), (int) keyData.getBlockSize());
        return new ParametersWithIV(new KeyParameter(keyValue), iv);
    }

    private byte[] decryptVerifierHashInput(byte[] _pwdBytes) {
        // OC: 2.3.4.13 (part 1)
        byte[] key = cryptDeriveKey(_pwdBytes, ENC_VERIFIER_INPUT_BLOCK, pwdKeyEnc.getSaltValue(), (int) pwdKeyEnc.getSpinCount(), bits2bytes((int) pwdKeyEnc.getKeyBits()));

        return blockDecryptBytes(key, pwdKeyEnc.getSaltValue(), pwdKeyEnc.getEncryptedVerifierHashInput());
    }

    private byte[] decryptVerifierHashValue(byte[] _pwdBytes) {
        // OC: 2.3.4.13 (part 2)
        byte[] key = cryptDeriveKey(_pwdBytes, ENC_VERIFIER_VALUE_BLOCK, pwdKeyEnc.getSaltValue(), (int) pwdKeyEnc.getSpinCount(), bits2bytes((int) pwdKeyEnc.getKeyBits()));

        return blockDecryptBytes(key, pwdKeyEnc.getSaltValue(), pwdKeyEnc.getEncryptedVerifierHashValue());
    }

    private byte[] decryptKeyValue(byte[] _pwdBytes) {
        // OC: 2.3.4.13 (part 3)
        byte[] key = cryptDeriveKey(_pwdBytes, ENC_VALUE_BLOCK, pwdKeyEnc.getSaltValue(), (int) pwdKeyEnc.getSpinCount(), bits2bytes((int) pwdKeyEnc.getKeyBits()));

        return blockDecryptBytes(key, pwdKeyEnc.getSaltValue(), pwdKeyEnc.getEncryptedKeyValue());
    }

    private byte[] cryptDeriveKey(byte[] _pwdBytes, byte[] _blockBytes, byte[] _salt, int _iterations, int _keyByteLen) {
        Digest digest = getDigest();

        // OC: 2.3.4.11
        byte[] baseHash = hash(digest, _salt, _pwdBytes);

        byte[] iterHash = iterateHash(baseHash, _iterations);

        byte[] finalHash = hash(digest, iterHash, _blockBytes);

        return fixToLength(finalHash, _keyByteLen, 0x36);
    }

    private byte[] cryptDeriveIV(byte[] _blockBytes, byte[] _salt, int _keyByteLen) {
        // OC: 2.3.4.12
        byte[] ivBytes = _blockBytes != null ? hash(getDigest(), _salt, _blockBytes) : _salt;

        return fixToLength(ivBytes, _keyByteLen, 0x36);
    }

}
