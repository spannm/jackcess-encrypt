package io.github.spannm.jackcess.encrypt;

import static io.github.spannm.jackcess.test.TestUtil.assertTable;
import static io.github.spannm.jackcess.test.TestUtil.createExpectedRow;
import static io.github.spannm.jackcess.test.TestUtil.createExpectedTable;
import static io.github.spannm.jackcess.test.TestUtil.createTempFile;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.spannm.jackcess.Database;
import io.github.spannm.jackcess.DatabaseBuilder;
import io.github.spannm.jackcess.Row;
import io.github.spannm.jackcess.Table;
import io.github.spannm.jackcess.impl.DatabaseImpl;
import io.github.spannm.jackcess.test.AbstractBaseTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

final class CryptCodecProviderTest extends AbstractBaseTest {

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/money2001.mny", "src/test/resources/data/money2001-pwd.mny"})
    void msisam2001(String dbFileName) throws Exception {

        assertThrows(UnsupportedOperationException.class,
            () -> new DatabaseBuilder().withFile(new File(dbFileName)).withReadOnly(true).open());

        try (Database db = open(dbFileName, true, null)) {
            doCheckMSISAM2001Db(db);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/money2002.mny"})
    void msisam2002(String dbFileName) throws Exception {
        try (Database db = open(dbFileName, true, null)) {
            doCheckMSISAM2002Db(db);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/money2008.mny"})
    void msisam2008(String dbFileName) throws Exception {
        try (Database db = open("src/test/resources/data/money2008.mny", true, null)) {
            doCheckMSISAM2008Db(db);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/money2008-pwd.mny"})
    void msisam2008Password(String dbFileName) throws Exception {
        IllegalStateException ex1 = assertThrows(IllegalStateException.class, () -> open(dbFileName, true, null));
        assertThat(ex1.getMessage()).isEqualTo("Incorrect password provided");

        IllegalStateException ex2 = assertThrows(IllegalStateException.class, () -> open(dbFileName, true, "WrongPassword"));
        assertThat(ex2.getMessage()).isEqualTo("Incorrect password provided");

        try (Database db = open(dbFileName, true, "Test12345")) {
            doCheckMSISAM2008Db(db);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/db-enc.mdb"})
    void readJet2000(String dbFileName) throws Exception {
        assertThrows(UnsupportedOperationException.class,
            () -> new DatabaseBuilder().withFile(new File(dbFileName)).withReadOnly(true).open());

        try (Database db = open(dbFileName, true, null)) {
            assertThat(db.getFileFormat()).isEqualTo(Database.FileFormat.V2000);

            doCheckJetDb(db, 0);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/db97-enc.mdb"})
    void readJet1997(String dbFileName) throws Exception {
        assertThrows(UnsupportedOperationException.class,
            () -> new DatabaseBuilder().withFile(new File(dbFileName)).withReadOnly(true).open());

        try (Database db = open(dbFileName, true, null)) {
            assertThat(db.getFileFormat()).isEqualTo(Database.FileFormat.V1997);

            doCheckJetDb(db, 0);
        }
    }

    @Test
    void writeJet() throws Exception {
        try (Database db = openCopy("src/test/resources/data/db-enc.mdb", null)) {
            Table t = db.getTable("Table1");

            ((DatabaseImpl) db).getPageChannel().startWrite();
            try {
                for (int i = 0; i < 1000; ++i) {
                    t.addRow(null, "this is the value of col1 " + i, i);
                }
            } finally {
                ((DatabaseImpl) db).getPageChannel().finishWrite();
            }

            db.flush();

            doCheckJetDb(db, 1000);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/db2007-oldenc.accdb", "src/test/resources/data/db2007-enc.accdb"})
    void readOfficeEnc(String dbFileName) throws Exception {
        assertThrows(UnsupportedOperationException.class,
            () -> new DatabaseBuilder().withFile(new File(dbFileName)).withReadOnly(true).open());

        IllegalStateException ex1 = assertThrows(IllegalStateException.class, () -> open(dbFileName, true, null));
        assertThat(ex1.getMessage()).isEqualTo("Incorrect password provided");

        IllegalStateException ex2 = assertThrows(IllegalStateException.class, () -> open(dbFileName, true, "WrongPassword"));
        assertThat(ex2.getMessage()).isEqualTo("Incorrect password provided");

        try (Database db = open(dbFileName, true, "Test123")) {
            db.getSystemTable("MSysQueries");
            doCheckOfficeDb(db, 0);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/db2013-enc.accdb"})
    void readOfficeEnc2013(String dbFileName) throws Exception {
        try (Database db = open(dbFileName, true, "1234")) {
            db.getSystemTable("MSysQueries");
            doCheckOffice2013Db(db, 0);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/db2007-oldenc.accdb", "src/test/resources/data/db2007-enc.accdb"})
    void writeOfficeEnc(String dbFileName) throws Exception {
        try (Database db = openCopy(dbFileName, "Test123")) {
            Table t = db.getTable("Table1");

            ((DatabaseImpl) db).getPageChannel().startWrite();
            try {
                for (int i = 0; i < 1000; ++i) {
                    t.addRow(null, "this is the value of col1 " + i);
                }
            } finally {
                ((DatabaseImpl) db).getPageChannel().finishWrite();
            }

            db.flush();

            doCheckOfficeDb(db, 1000);
        }
    }

    @Test
    void passwordCallback() throws Exception {
        AtomicInteger count = new AtomicInteger();
        PasswordCallback pc = () -> {
            count.incrementAndGet();
            return "Test123";
        };

        Database db = new DatabaseBuilder()
            .withFile(new File("src/test/resources/data/db-enc.mdb"))
            .withReadOnly(true).withCodecProvider(new CryptCodecProvider(pc)).open();

        Table t = db.getTable("Table1");
        assertThat(t).isNotNull();

        assertThat(count.get()).isEqualTo(0);

        CryptCodecProvider cryptCodecProvider = new CryptCodecProvider();
        cryptCodecProvider.setPasswordCallback(pc);
        db = new DatabaseBuilder()
            .withFile(new File("src/test/resources/data/db2007-enc.accdb"))
            .withReadOnly(true)
            .withCodecProvider(cryptCodecProvider).open();

        t = db.getTable("Table1");
        assertThat(t).isNotNull();

        assertThat(count.get()).isEqualTo(1);
    }

    @Test
    void nonStandardProvider() throws Exception {
        String fname = "src/test/resources/data/db-nonstandard.accdb";

        assertThrows(UnsupportedOperationException.class, () -> new DatabaseBuilder().withFile(new File(fname)).withReadOnly(true).open());

        InvalidCredentialsException ex1 = assertThrows(InvalidCredentialsException.class, () -> open(fname, true, null));
        assertThat(ex1.getMessage()).isEqualTo("Incorrect password provided");

        InvalidCredentialsException ex2 = assertThrows(InvalidCredentialsException.class, () -> open(fname, true, "WrongPassword"));
        assertThat(ex2.getMessage()).isEqualTo("Incorrect password provided");

        try (Database db = open(fname, true, "password")) {
            db.getSystemTable("MSysQueries");

            Table t = db.getTable("Table_One");

            assertThat(t.getColumn("ID")).isNotNull();
        }
    }

    private static void doCheckJetDb(Database db, int addedRows) throws Exception {
        Table t = db.getTable("Table1");

        List<Row> expectedRows = createExpectedTable(createExpectedRow("ID", 1, "col1", "hello", "col2", 0), createExpectedRow("ID", 2, "col1", "world", "col2", 42));

        if (addedRows > 0) {
            int nextId = 3;
            for (int i = 0; i < addedRows; ++i) {
                expectedRows.add(createExpectedRow("ID", nextId++, "col1", "this is the value of col1 " + i, "col2", i));
            }
        }

        assertTable(expectedRows, t);
    }

    private static void doCheckOfficeDb(Database db, int addedRows) throws Exception {
        Table t = db.getTable("Table1");

        List<Row> expectedRows = createExpectedTable(createExpectedRow("ID", 1, "Field1", "foo"));

        if (addedRows > 0) {
            int nextId = 2;
            for (int i = 0; i < addedRows; ++i) {
                expectedRows.add(createExpectedRow("ID", nextId++, "Field1", "this is the value of col1 " + i));
            }
        }

        assertTable(expectedRows, t);
    }

    private static void doCheckOffice2013Db(Database db, int addedRows) throws Exception {
        Table t = db.getTable("Customers");

        List<Row> expectedRows = createExpectedTable(createExpectedRow("ID", 1, "Field1", "Test"), createExpectedRow("ID", 2, "Field1", "Test2"),
            createExpectedRow("ID", 3, "Field1", "a"), createExpectedRow("ID", 4, "Field1", null), createExpectedRow("ID", 5, "Field1", "c"),
            createExpectedRow("ID", 6, "Field1", "d"), createExpectedRow("ID", 7, "Field1", "f"));

        if (addedRows > 0) {
            int nextId = 2;
            for (int i = 0; i < addedRows; ++i) {
                expectedRows.add(createExpectedRow("ID", nextId++, "Field1", "this is the value of col1 " + i));
            }
        }

        assertTable(expectedRows, t);
    }

    private static void doCheckMSISAM2001Db(Database db) throws Exception {
        assertThat(db.getFileFormat()).isEqualTo(Database.FileFormat.MSISAM);

        assertThat(db.getTableNames()).containsExactlyInAnyOrderElementsOf(Set.of(
            "ACCT", "ADDR", "ADV", "ADV_SUM", "Advisor Important Dates Custom Pool", "Asset Allocation Custom Pool", "AUTO", "AWD", "BGT", "BGT_BKT", "BGT_ITM", "CAT", "CESRC",
            "CLI", "CLI_DAT", "CNTRY", "CRIT", "CRNC", "CRNC_EXCHG", "CT", "DHD", "FI", "Goal Custom Pool", "Inventory Custom Pool", "ITM", "IVTY", "LOT", "LSTEP", "MAIL", "MCSRC", "PAY", "PGM",
            "PMT", "PORT_REC", "Portfolio View Custom Pool", "POS_STMT", "PRODUCT", "PROJ", "PROV_FI", "PROV_FI_PAY", "Report Custom Pool", "SAV_GOAL", "SEC", "SEC_SPLIT", "SIC", "SOQ", "SP", "STMT",
            "SVC", "Tax Rate Custom Pool", "TAXLINE", "TMI", "TRIP", "TRN", "TRN_INV", "TRN_INVOICE", "TRN_OL", "TRN_SPLIT", "TRN_XFER", "TXSRC", "VIEW", "Worksheet Custom Pool", "XACCT", "XMAPACCT",
            "XMAPSAT", "XPAY"));

        Table t = db.getTable("CRNC");

        Set<String> cols = Set.of("hcrnc", "szName", "lcid", "szIsoCode", "szSymbol");

        assertThat(t.getDefaultCursor().getNextRow(cols)).isEqualTo(createExpectedRow("hcrnc", 1, "szName", "Argentinean peso", "lcid", 11274, "szIsoCode", "ARS", "szSymbol", "/ARSUS"));

        assertThat(t.getDefaultCursor().getNextRow(cols)).isEqualTo(createExpectedRow("hcrnc", 2, "szName", "Australian dollar", "lcid", 3081, "szIsoCode", "AUD", "szSymbol", "/AUDUS"));

        assertThat(t.getDefaultCursor().getNextRow(cols)).isEqualTo(createExpectedRow("hcrnc", 3, "szName", "Austrian schilling", "lcid", 3079, "szIsoCode", "ATS", "szSymbol", "/ATSUS"));

        assertThat(t.getDefaultCursor().getNextRow(cols)).isEqualTo(createExpectedRow("hcrnc", 4, "szName", "Belgian franc", "lcid", 2060, "szIsoCode", "BEF", "szSymbol", "/BECUS"));
    }

    private static void doCheckMSISAM2002Db(Database db) throws Exception {
        assertThat(db.getFileFormat()).isEqualTo(Database.FileFormat.MSISAM);

        assertThat(db.getTableNames()).containsExactlyInAnyOrderElementsOf(Set.of(
            "ACCT", "ADDR", "ADV", "ADV_SUM", "Advisor Important Dates Custom Pool", "Asset Allocation Custom Pool", "AUTO", "AWD", "BGT", "BGT_BKT", "BGT_ITM", "BILL", "BILL_FLD",
            "CAT", "CESRC", "CLI", "CLI_DAT", "CNTRY", "CRIT", "CRNC", "CRNC_EXCHG", "CT", "DHD", "FI", "Goal Custom Pool", "Inventory Custom Pool", "ITM", "IVTY", "LOT", "LSTEP", "MAIL", "MCSRC",
            "PAY", "PGM", "PMT", "PORT_REC", "Portfolio View Custom Pool", "POS_STMT", "PRODUCT", "PROJ", "PROV_FI", "PROV_FI_PAY", "Report Custom Pool", "SAV_GOAL", "SEC", "SEC_SPLIT", "SIC",
            "SOQ", "SP", "STMT", "SVC", "Tax Rate Custom Pool", "TAXLINE", "TMI", "TRIP", "TRN", "TRN_INV", "TRN_INVOICE", "TRN_OL", "TRN_SPLIT", "TRN_XFER", "TXSRC", "UIE", "UKSavings", "UKWiz",
            "UKWizAddress", "UKWizCompanyCar", "UKWizLoan", "UKWizMortgage", "UKWizPenScheme", "UKWizPension", "UKWizWillExecutor", "UKWizWillGift", "UKWizWillGuardian", "UKWizWillLovedOne",
            "UKWizWillMaker", "UKWizWillPerson", "UKWizWillResidue", "UNOTE", "VIEW", "Worksheet Custom Pool", "XACCT", "XBAG", "XMAPACCT", "XMAPSAT", "XPAY"));

        Table t = db.getTable("CRNC");

        Set<String> cols = Set.of("hcrnc", "szName", "lcid", "szIsoCode", "szSymbol");

        assertThat(t.getDefaultCursor().getNextRow(cols)).isEqualTo(createExpectedRow("hcrnc", 1, "szName", "Argentinian peso", "lcid", 11274, "szIsoCode", "ARS", "szSymbol", "/ARSUS"));

        assertThat(t.getDefaultCursor().getNextRow(cols)).isEqualTo(createExpectedRow("hcrnc", 2, "szName", "Australian dollar", "lcid", 3081, "szIsoCode", "AUD", "szSymbol", "/AUDUS"));

        assertThat(t.getDefaultCursor().getNextRow(cols)).isEqualTo(createExpectedRow("hcrnc", 3, "szName", "Austrian schilling", "lcid", 3079, "szIsoCode", "ATS", "szSymbol", "/ATSUS"));

        assertThat(t.getDefaultCursor().getNextRow(cols)).isEqualTo(createExpectedRow("hcrnc", 4, "szName", "Belgian franc", "lcid", 2060, "szIsoCode", "BEF", "szSymbol", "/BECUS"));
    }

    private static void doCheckMSISAM2008Db(Database db) throws Exception {
        assertThat(db.getFileFormat()).isEqualTo(Database.FileFormat.MSISAM);

        assertThat(db.getTableNames()).containsExactlyInAnyOrderElementsOf(Set.of(
            "ACCT", "ADDR", "ADV", "ADV_SUM", "Advisor Important Dates Custom Pool", "Asset Allocation Custom Pool", "AUTO", "AWD", "BGT", "BGT_BKT", "BGT_ITM", "BILL",
            "BILL_FLD", "CAT", "CESRC", "CLI", "CLI_DAT", "CNTRY", "CRIT", "CRNC", "CRNC_EXCHG", "CT", "DHD", "Feature Expiration Custom Pool", "FI", "Inventory Custom Pool", "ITM", "IVTY", "LOT",
            "LSTEP", "MAIL", "MCSRC", "PAY", "PGM", "PM_RPT", "PMT", "PORT_REC", "Portfolio View Custom Pool", "POS_STMT", "PREF", "PREF_LIST", "PRODUCT", "PROJ", "PROV_FI", "PROV_FI_PAY",
            "Report Custom Pool", "SAV_GOAL", "SCHE_TASK", "SEC", "SEC_SPLIT", "SIC", "SOQ", "SP", "STMT", "SVC", "Tax Rate Custom Pool", "Tax Scenario Custom Pool", "TAXLINE", "TMI", "TRIP", "TRN",
            "TRN_INV", "TRN_INVOICE", "TRN_OL", "TRN_SPLIT", "TRN_XFER", "TXSRC", "UI_VIEW", "UIE", "UNOTE", "VIEW", "Worksheet Custom Pool", "X_FMLA", "X_ITM", "X_META_REF", "X_PARM", "XACCT",
            "XBAG", "XMAPACCT", "XMAPSAT", "XMAPSEC", "XPAY", "XSYNCCHUNK"));

        Table t = db.getTable("CRNC");

        Set<String> cols = Set.of("hcrnc", "szName", "lcid", "szIsoCode", "szSymbol");

        assertThat(t.getDefaultCursor().getNextRow(cols)).isEqualTo(createExpectedRow("hcrnc", 1, "szName", "Argentine peso", "lcid", 11274, "szIsoCode", "ARS", "szSymbol", "/ARSUS"));

        assertThat(t.getDefaultCursor().getNextRow(cols)).isEqualTo(createExpectedRow("hcrnc", 2, "szName", "Australian dollar", "lcid", 3081, "szIsoCode", "AUD", "szSymbol", "/AUDUS"));

        assertThat(t.getDefaultCursor().getNextRow(cols)).isEqualTo(createExpectedRow("hcrnc", 3, "szName", "Austrian schilling", "lcid", 3079, "szIsoCode", "ATS", "szSymbol", "/ATSUS"));

        assertThat(t.getDefaultCursor().getNextRow(cols)).isEqualTo(createExpectedRow("hcrnc", 4, "szName", "Belgian franc", "lcid", 2060, "szIsoCode", "BEF", "szSymbol", "/BEFUS"));
    }

    Database openCopy(String fileName, String pwd) throws Exception {
        File copy = createTempFile(getShortTestMethodName(), ".tmp", false);
        Files.copy(new File(fileName).toPath(), copy.toPath(), StandardCopyOption.REPLACE_EXISTING);
        return open(copy.getPath(), false, pwd);
    }

    static Database open(String _fileName, boolean _readOnly, String _pwd) throws Exception {
        return CryptCodecUtil.withCodecProvider(new DatabaseBuilder()
            .withFile(new File(_fileName))
            .withReadOnly(_readOnly),
            _pwd).open();
    }

    static void checkCryptoStrength() {
        boolean unlimitedCrypto = false;
        try {
            unlimitedCrypto = javax.crypto.Cipher.getMaxAllowedKeyLength("AES") > 256;
        } catch (Exception _ex) {}
        System.out.println("Unlimited strength cryptography: " + unlimitedCrypto);
    }
}
