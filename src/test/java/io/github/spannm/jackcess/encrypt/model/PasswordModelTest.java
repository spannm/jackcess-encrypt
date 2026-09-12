package io.github.spannm.jackcess.encrypt.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spannm.jackcess.encrypt.model.password.CTPasswordKeyEncryptor;
import io.github.spannm.jackcess.encrypt.model.password.STPasswordKeyEncryptorUri;
import org.junit.jupiter.api.Test;

final class PasswordModelTest {

    @Test
    void passwordKeyEncryptorGettersAndSetters() {
        CTPasswordKeyEncryptor enc = new CTPasswordKeyEncryptor();

        byte[] saltValue = {1, 2, 3};
        byte[] verifierHashInput = {4, 5, 6};
        byte[] verifierHashValue = {7, 8, 9};
        byte[] encryptedKeyValue = {10, 11, 12};

        enc.setSaltSize(16L);
        enc.setBlockSize(16L);
        enc.setKeyBits(128L);
        enc.setHashSize(20L);
        enc.setCipherAlgorithm("AES");
        enc.setCipherChaining("ChainingModeCBC");
        enc.setHashAlgorithm("SHA1");
        enc.setSaltValue(saltValue);
        enc.setSpinCount(100000L);
        enc.setEncryptedVerifierHashInput(verifierHashInput);
        enc.setEncryptedVerifierHashValue(verifierHashValue);
        enc.setEncryptedKeyValue(encryptedKeyValue);

        assertThat(enc.getSaltSize()).isEqualTo(16L);
        assertThat(enc.getBlockSize()).isEqualTo(16L);
        assertThat(enc.getKeyBits()).isEqualTo(128L);
        assertThat(enc.getHashSize()).isEqualTo(20L);
        assertThat(enc.getCipherAlgorithm()).isEqualTo("AES");
        assertThat(enc.getCipherChaining()).isEqualTo("ChainingModeCBC");
        assertThat(enc.getHashAlgorithm()).isEqualTo("SHA1");
        assertThat(enc.getSaltValue()).isEqualTo(saltValue);
        assertThat(enc.getSpinCount()).isEqualTo(100000L);
        assertThat(enc.getEncryptedVerifierHashInput()).isEqualTo(verifierHashInput);
        assertThat(enc.getEncryptedVerifierHashValue()).isEqualTo(verifierHashValue);
        assertThat(enc.getEncryptedKeyValue()).isEqualTo(encryptedKeyValue);
    }

    @Test
    void passwordKeyEncryptorUriFromValue() {
        STPasswordKeyEncryptorUri uri = STPasswordKeyEncryptorUri
            .fromValue("http://schemas.microsoft.com/office/2006/keyEncryptor/password");

        assertThat(uri).isEqualTo(STPasswordKeyEncryptorUri.HTTP_SCHEMAS_MICROSOFT_COM_OFFICE_2006_KEY_ENCRYPTOR_PASSWORD);
        assertThat(uri.value()).isEqualTo("http://schemas.microsoft.com/office/2006/keyEncryptor/password");
    }

    @Test
    void passwordKeyEncryptorUriFromValueUnknown() {
        assertThatThrownBy(() -> STPasswordKeyEncryptorUri.fromValue("unknown"))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
