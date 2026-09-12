package io.github.spannm.jackcess.encrypt;

import static io.github.spannm.jackcess.test.TestUtil.createTempFile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spannm.jackcess.Database;
import io.github.spannm.jackcess.DatabaseBuilder;
import io.github.spannm.jackcess.Table;
import io.github.spannm.jackcess.test.AbstractBaseTest;
import org.junit.jupiter.api.Test;

import java.io.File;

@SuppressWarnings("PMD.LinguisticNaming")
final class CryptCodecProviderExtraTest extends AbstractBaseTest {

    @Test
    void supplierConstructor() throws Exception {
        CryptCodecProvider provider = new CryptCodecProvider(() -> "Test123");

        try (Database db = new DatabaseBuilder()
            .withFile(new File("src/test/resources/data/db2007-enc.accdb"))
            .withReadOnly(true)
            .withCodecProvider(provider).open()) {

            Table t = db.getTable("Table1");
            assertThat(t).isNotNull();
        }
    }

    @Test
    void setPassword() throws Exception {
        CryptCodecProvider provider = new CryptCodecProvider();
        provider.setPassword("Test123");

        try (Database db = new DatabaseBuilder()
            .withFile(new File("src/test/resources/data/db2007-enc.accdb"))
            .withReadOnly(true)
            .withCodecProvider(provider).open()) {

            Table t = db.getTable("Table1");
            assertThat(t).isNotNull();
        }
    }

    @Test
    void getPasswordCallback() {
        PasswordCallback pc = () -> "Test123";
        CryptCodecProvider provider = new CryptCodecProvider(pc);

        assertThat(provider.getPasswordCallback()).isSameAs(pc);
        assertThat(provider.getPasswordSupplier()).isSameAs(pc);
    }

    @Test
    void getPasswordCallbackClassCastException() {
        CryptCodecProvider provider = new CryptCodecProvider();
        provider.setPasswordSupplier(() -> "Test123");

        assertThatThrownBy(provider::getPasswordCallback).isInstanceOf(ClassCastException.class);
    }

    @Test
    @SuppressWarnings("PMD.EmptyBlock")
    void unencryptedDatabaseUsesDummyHandler() throws Exception {
        File dbFile = createTempFile(getShortTestMethodName(), ".accdb", false);

        try (Database ignored = DatabaseBuilder.create(Database.FileFormat.V2010, dbFile)) {
            // just create it
        }

        try (Database db = CryptCodecUtil.withCodecProvider(new DatabaseBuilder().withFile(dbFile)).open()) {
            assertThat(db.getFileFormat()).isEqualTo(Database.FileFormat.V2010);
        }
    }

    @Test
    @SuppressWarnings("PMD.EmptyBlock")
    void withCodecProviderExplicitNullPassword() throws Exception {
        File dbFile = createTempFile(getShortTestMethodName(), ".accdb", false);

        try (Database ignored = DatabaseBuilder.create(Database.FileFormat.V2010, dbFile)) {
            // just create it
        }

        try (Database db = CryptCodecUtil.withCodecProvider(new DatabaseBuilder().withFile(dbFile), null).open()) {
            assertThat(db.getFileFormat()).isEqualTo(Database.FileFormat.V2010);
        }
    }

    @Test
    void invalidCryptoConfigurationExceptionWithCause() {
        Exception cause = new IllegalArgumentException("root cause");
        InvalidCryptoConfigurationException ex = new InvalidCryptoConfigurationException("bad config", cause);

        assertThat(ex.getMessage()).isEqualTo("bad config");
        assertThat(ex.getCause()).isSameAs(cause);
    }
}
