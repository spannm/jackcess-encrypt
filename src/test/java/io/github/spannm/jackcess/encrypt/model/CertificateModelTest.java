package io.github.spannm.jackcess.encrypt.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spannm.jackcess.encrypt.model.cert.CTCertificateKeyEncryptor;
import io.github.spannm.jackcess.encrypt.model.cert.STCertificateKeyEncryptorUri;
import org.junit.jupiter.api.Test;

final class CertificateModelTest {

    @Test
    void certificateKeyEncryptorGettersAndSetters() {
        CTCertificateKeyEncryptor enc = new CTCertificateKeyEncryptor();

        byte[] encryptedKeyValue = {1, 2, 3};
        byte[] x509Certificate = {4, 5, 6};
        byte[] certVerifier = {7, 8, 9};

        enc.setEncryptedKeyValue(encryptedKeyValue);
        enc.setX509Certificate(x509Certificate);
        enc.setCertVerifier(certVerifier);

        assertThat(enc.getEncryptedKeyValue()).isEqualTo(encryptedKeyValue);
        assertThat(enc.getX509Certificate()).isEqualTo(x509Certificate);
        assertThat(enc.getCertVerifier()).isEqualTo(certVerifier);
    }

    @Test
    void certificateKeyEncryptorUriFromValue() {
        STCertificateKeyEncryptorUri uri = STCertificateKeyEncryptorUri
            .fromValue("http://schemas.microsoft.com/office/2006/keyEncryptor/certificate");

        assertThat(uri).isEqualTo(STCertificateKeyEncryptorUri.HTTP_SCHEMAS_MICROSOFT_COM_OFFICE_2006_KEY_ENCRYPTOR_CERTIFICATE);
        assertThat(uri.value()).isEqualTo("http://schemas.microsoft.com/office/2006/keyEncryptor/certificate");
    }

    @Test
    void certificateKeyEncryptorUriFromValueUnknown() {
        assertThatThrownBy(() -> STCertificateKeyEncryptorUri.fromValue("unknown"))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
