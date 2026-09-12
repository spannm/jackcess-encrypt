package io.github.spannm.jackcess.encrypt.model;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

final class EncryptionModelTest {

    @Test
    void keyDataGettersAndSetters() {
        CTKeyData keyData = new CTKeyData();
        byte[] saltValue = {1, 2, 3};

        keyData.setSaltSize(16L);
        keyData.setBlockSize(16L);
        keyData.setKeyBits(128L);
        keyData.setHashSize(20L);
        keyData.setCipherAlgorithm("AES");
        keyData.setCipherChaining("ChainingModeCBC");
        keyData.setHashAlgorithm("SHA1");
        keyData.setSaltValue(saltValue);

        assertThat(keyData.getSaltSize()).isEqualTo(16L);
        assertThat(keyData.getBlockSize()).isEqualTo(16L);
        assertThat(keyData.getKeyBits()).isEqualTo(128L);
        assertThat(keyData.getHashSize()).isEqualTo(20L);
        assertThat(keyData.getCipherAlgorithm()).isEqualTo("AES");
        assertThat(keyData.getCipherChaining()).isEqualTo("ChainingModeCBC");
        assertThat(keyData.getHashAlgorithm()).isEqualTo("SHA1");
        assertThat(keyData.getSaltValue()).isEqualTo(saltValue);
    }

    @Test
    void dataIntegrityGettersAndSetters() {
        CTDataIntegrity dataIntegrity = new CTDataIntegrity();
        byte[] hmacKey = {1, 2, 3};
        byte[] hmacValue = {4, 5, 6};

        dataIntegrity.setEncryptedHmacKey(hmacKey);
        dataIntegrity.setEncryptedHmacValue(hmacValue);

        assertThat(dataIntegrity.getEncryptedHmacKey()).isEqualTo(hmacKey);
        assertThat(dataIntegrity.getEncryptedHmacValue()).isEqualTo(hmacValue);
    }

    @Test
    void keyEncryptorGettersAndSetters() {
        CTKeyEncryptor keyEncryptor = new CTKeyEncryptor();
        Object any = new Object();

        keyEncryptor.setAny(any);
        keyEncryptor.setUri("http://schemas.microsoft.com/office/2006/keyEncryptor/password");

        assertThat(keyEncryptor.getAny()).isSameAs(any);
        assertThat(keyEncryptor.getUri()).isEqualTo("http://schemas.microsoft.com/office/2006/keyEncryptor/password");
    }

    @Test
    void keyEncryptorsLazyList() {
        CTKeyEncryptors keyEncryptors = new CTKeyEncryptors();
        assertThat(keyEncryptors.getKeyEncryptor()).isEmpty();

        CTKeyEncryptor keyEncryptor = new CTKeyEncryptor();
        keyEncryptors.getKeyEncryptor().add(keyEncryptor);

        assertThat(keyEncryptors.getKeyEncryptor()).containsExactly(keyEncryptor);
    }

    @Test
    void encryptionGettersAndSetters() {
        CTEncryption encryption = new CTEncryption();
        CTKeyData keyData = new CTKeyData();
        CTDataIntegrity dataIntegrity = new CTDataIntegrity();
        CTKeyEncryptors keyEncryptors = new CTKeyEncryptors();

        encryption.setKeyData(keyData);
        encryption.setDataIntegrity(dataIntegrity);
        encryption.setKeyEncryptors(keyEncryptors);

        assertThat(encryption.getKeyData()).isSameAs(keyData);
        assertThat(encryption.getDataIntegrity()).isSameAs(dataIntegrity);
        assertThat(encryption.getKeyEncryptors()).isSameAs(keyEncryptors);
    }
}
