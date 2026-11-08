package io.github.spannm.jackcess.encrypt.impl.office;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spannm.jackcess.encrypt.InvalidCryptoConfigurationException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@SuppressWarnings({"checkstyle:MethodName", "PMD.LinguisticNaming"})
final class XmlEncryptionDescriptorTest {

    // names starting with a digit map to the underscore prefixed enum constants
    @ParameterizedTest(name = "[{index}] {0} {1}")
    @CsvSource({
        "AES,      ChainingModeCBC, AES/CBC",
        "3DES,     ChainingModeCBC, DESede/CBC",
        "3DES_112, ChainingModeECB, DESede",
        "des,      ChainingModeCFB, DES/CFB"
    })
    void initCipher_validNames_matchingCipher(String cipher, String chaining, String expectedName) {
        assertThat(XmlEncryptionDescriptor.initCipher(cipher, chaining).getAlgorithmName()).startsWith(expectedName);
    }

    @ParameterizedTest(name = "[{index}] ''{0}''")
    @ValueSource(strings = {"", "  ", "Blowfish"})
    void initCipher_unknownAlgorithm_throws(String cipher) {
        assertThatThrownBy(() -> XmlEncryptionDescriptor.initCipher(cipher, "ChainingModeCBC"))
            .isInstanceOf(InvalidCryptoConfigurationException.class)
            .hasMessageStartingWith("Unsupported encryption parameter");
    }
}
