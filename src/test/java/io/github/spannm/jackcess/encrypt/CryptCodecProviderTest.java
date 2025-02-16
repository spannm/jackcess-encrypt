package io.github.spannm.jackcess.encrypt;

import static io.github.spannm.jackcess.test.TestUtil.*;

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

class CryptCodecProviderTest extends AbstractBaseTest {

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/money2001.mny", "src/test/resources/data/money2001-pwd.mny"})
    void testMSISAM2001(String dbFileName) throws Exception {

        assertThrows(UnsupportedOperationException.class,
            () -> new DatabaseBuilder().withFile(new File(dbFileName)).withReadOnly(true).open());

        try (Database db = open(dbFileName, true, null)) {
            doCheckMSISAM2001Db(db);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/money2002.mny"})
    void testMSISAM2002(String dbFileName) throws Exception {
        try (Database db = open(dbFileName, true, null)) {
            doCheckMSISAM2002Db(db);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/money2008.mny"})
    void testMSISAM2008(String dbFileName) throws Exception {
        try (Database db = open("src/test/resources/data/money2008.mny", true, null)) {
            doCheckMSISAM2008Db(db);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/money2008-pwd.mny"})
    void testMSISAM2008Password(String dbFileName) throws Exception {
        IllegalStateException ex1 = assertThrows(IllegalStateException.class, () -> open(dbFileName, true, null));
        assertEquals("Incorrect password provided", ex1.getMessage());

        IllegalStateException ex2 = assertThrows(IllegalStateException.class, () -> open(dbFileName, true, "WrongPassword"));
        assertEquals("Incorrect password provided", ex2.getMessage());

        try (Database db = open(dbFileName, true, "Test12345")) {
            doCheckMSISAM2008Db(db);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/db-enc.mdb"})
    void testReadJet2000(String dbFileName) throws Exception {
        assertThrows(UnsupportedOperationException.class,
            () -> new DatabaseBuilder().withFile(new File(dbFileName)).withReadOnly(true).open());

        try (Database db = open(dbFileName, true, null)) {
            assertEquals(Database.FileFormat.V2000, db.getFileFormat());

            doCheckJetDb(db, 0);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/db97-enc.mdb"})
    void testReadJet1997(String dbFileName) throws Exception {
        assertThrows(UnsupportedOperationException.class,
            () -> new DatabaseBuilder().withFile(new File(dbFileName)).withReadOnly(true).open());

        try (Database db = open(dbFileName, true, null)) {
            assertEquals(Database.FileFormat.V1997, db.getFileFormat());

            doCheckJetDb(db, 0);
        }
    }

    @Test
    void testWriteJet() throws Exception {
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
    void testReadOfficeEnc(String dbFileName) throws Exception {
        assertThrows(UnsupportedOperationException.class,
            () -> new DatabaseBuilder().withFile(new File(dbFileName)).withReadOnly(true).open());

        IllegalStateException ex1 = assertThrows(IllegalStateException.class, () -> open(dbFileName, true, null));
        assertEquals("Incorrect password provided", ex1.getMessage());

        IllegalStateException ex2 = assertThrows(IllegalStateException.class, () -> open(dbFileName, true, "WrongPassword"));
        assertEquals("Incorrect password provided", ex2.getMessage());

        try (Database db = open(dbFileName, true, "Test123")) {
            db.getSystemTable("MSysQueries");
            doCheckOfficeDb(db, 0);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/db2013-enc.accdb"})
    void testReadOfficeEnc2013(String dbFileName) throws Exception {
        try (Database db = open(dbFileName, true, "1234")) {
            db.getSystemTable("MSysQueries");
            doCheckOffice2013Db(db, 0);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"src/test/resources/data/db2007-oldenc.accdb", "src/test/resources/data/db2007-enc.accdb"})
    void testWriteOfficeEnc(String dbFileName) throws Exception {
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
    void testPasswordCallback() throws Exception {
        AtomicInteger count = new AtomicInteger();
        PasswordCallback pc = new PasswordCallback() {
            @Override
            public String getPassword() {
                count.incrementAndGet();
                return "Test123";
            }
        };

        Database db = new DatabaseBuilder()
            .withFile(new File("src/test/resources/data/db-enc.mdb"))
            .withReadOnly(true).withCodecProvider(new CryptCodecProvider(pc)).open();

        Table t = db.getTable("Table1");
        assertNotNull(t);

        assertEquals(0, count.get());

        CryptCodecProvider cryptCodecProvider = new CryptCodecProvider();
        cryptCodecProvider.setPasswordCallback(pc);
        db = new DatabaseBuilder()
            .withFile(new File("src/test/resources/data/db2007-enc.accdb"))
            .withReadOnly(true)
            .withCodecProvider(cryptCodecProvider).open();

        t = db.getTable("Table1");
        assertNotNull(t);

        assertEquals(1, count.get());
    }

    @Test
    void testNonStandardProvider() throws Exception {
        String fname = "src/test/resources/data/db-nonstandard.accdb";

        assertThrows(UnsupportedOperationException.class, () -> new DatabaseBuilder().withFile(new File(fname)).withReadOnly(true).open());

        InvalidCredentialsException ex1 = assertThrows(InvalidCredentialsException.class, () -> open(fname, true, null));
        assertEquals("Incorrect password provided", ex1.getMessage());

        InvalidCredentialsException ex2 = assertThrows(InvalidCredentialsException.class, () -> open(fname, true, "WrongPassword"));
        assertEquals("Incorrect password provided", ex2.getMessage());

        try (Database db = open(fname, true, "password")) {
            db.getSystemTable("MSysQueries");

            Table t = db.getTable("Table_One");

            assertNotNull(t.getColumn("ID"));
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
        assertEquals(Database.FileFormat.MSISAM, db.getFileFormat());

        assertEquals(Set.of("ACCT", "ADDR", "ADV", "ADV_SUM", "Advisor Important Dates Custom Pool", "Asset Allocation Custom Pool", "AUTO", "AWD", "BGT", "BGT_BKT", "BGT_ITM", "CAT", "CESRC",
            "CLI", "CLI_DAT", "CNTRY", "CRIT", "CRNC", "CRNC_EXCHG", "CT", "DHD", "FI", "Goal Custom Pool", "Inventory Custom Pool", "ITM", "IVTY", "LOT", "LSTEP", "MAIL", "MCSRC", "PAY", "PGM",
            "PMT", "PORT_REC", "Portfolio View Custom Pool", "POS_STMT", "PRODUCT", "PROJ", "PROV_FI", "PROV_FI_PAY", "Report Custom Pool", "SAV_GOAL", "SEC", "SEC_SPLIT", "SIC", "SOQ", "SP", "STMT",
            "SVC", "Tax Rate Custom Pool", "TAXLINE", "TMI", "TRIP", "TRN", "TRN_INV", "TRN_INVOICE", "TRN_OL", "TRN_SPLIT", "TRN_XFER", "TXSRC", "VIEW", "Worksheet Custom Pool", "XACCT", "XMAPACCT",
            "XMAPSAT", "XPAY"), db.getTableNames());

        Table t = db.getTable("CRNC");

        Set<String> cols = Set.of("hcrnc", "szName", "lcid", "szIsoCode", "szSymbol");

        assertEquals(createExpectedRow("hcrnc", 1, "szName", "Argentinean peso", "lcid", 11274, "szIsoCode", "ARS", "szSymbol", "/ARSUS"), t.getDefaultCursor().getNextRow(cols));

        assertEquals(createExpectedRow("hcrnc", 2, "szName", "Australian dollar", "lcid", 3081, "szIsoCode", "AUD", "szSymbol", "/AUDUS"), t.getDefaultCursor().getNextRow(cols));

        assertEquals(createExpectedRow("hcrnc", 3, "szName", "Austrian schilling", "lcid", 3079, "szIsoCode", "ATS", "szSymbol", "/ATSUS"), t.getDefaultCursor().getNextRow(cols));

        assertEquals(createExpectedRow("hcrnc", 4, "szName", "Belgian franc", "lcid", 2060, "szIsoCode", "BEF", "szSymbol", "/BECUS"), t.getDefaultCursor().getNextRow(cols));
    }

    private static void doCheckMSISAM2002Db(Database db) throws Exception {
        assertEquals(Database.FileFormat.MSISAM, db.getFileFormat());

        assertEquals(
            Set.of("ACCT", "ADDR", "ADV", "ADV_SUM", "Advisor Important Dates Custom Pool", "Asset Allocation Custom Pool", "AUTO", "AWD", "BGT", "BGT_BKT", "BGT_ITM", "BILL", "BILL_FLD",
                "CAT", "CESRC", "CLI", "CLI_DAT", "CNTRY", "CRIT", "CRNC", "CRNC_EXCHG", "CT", "DHD", "FI", "Goal Custom Pool", "Inventory Custom Pool", "ITM", "IVTY", "LOT", "LSTEP", "MAIL", "MCSRC",
                "PAY", "PGM", "PMT", "PORT_REC", "Portfolio View Custom Pool", "POS_STMT", "PRODUCT", "PROJ", "PROV_FI", "PROV_FI_PAY", "Report Custom Pool", "SAV_GOAL", "SEC", "SEC_SPLIT", "SIC",
                "SOQ", "SP", "STMT", "SVC", "Tax Rate Custom Pool", "TAXLINE", "TMI", "TRIP", "TRN", "TRN_INV", "TRN_INVOICE", "TRN_OL", "TRN_SPLIT", "TRN_XFER", "TXSRC", "UIE", "UKSavings", "UKWiz",
                "UKWizAddress", "UKWizCompanyCar", "UKWizLoan", "UKWizMortgage", "UKWizPenScheme", "UKWizPension", "UKWizWillExecutor", "UKWizWillGift", "UKWizWillGuardian", "UKWizWillLovedOne",
                "UKWizWillMaker", "UKWizWillPerson", "UKWizWillResidue", "UNOTE", "VIEW", "Worksheet Custom Pool", "XACCT", "XBAG", "XMAPACCT", "XMAPSAT", "XPAY"),
            db.getTableNames());

        Table t = db.getTable("CRNC");

        Set<String> cols = Set.of("hcrnc", "szName", "lcid", "szIsoCode", "szSymbol");

        assertEquals(createExpectedRow("hcrnc", 1, "szName", "Argentinian peso", "lcid", 11274, "szIsoCode", "ARS", "szSymbol", "/ARSUS"), t.getDefaultCursor().getNextRow(cols));

        assertEquals(createExpectedRow("hcrnc", 2, "szName", "Australian dollar", "lcid", 3081, "szIsoCode", "AUD", "szSymbol", "/AUDUS"), t.getDefaultCursor().getNextRow(cols));

        assertEquals(createExpectedRow("hcrnc", 3, "szName", "Austrian schilling", "lcid", 3079, "szIsoCode", "ATS", "szSymbol", "/ATSUS"), t.getDefaultCursor().getNextRow(cols));

        assertEquals(createExpectedRow("hcrnc", 4, "szName", "Belgian franc", "lcid", 2060, "szIsoCode", "BEF", "szSymbol", "/BECUS"), t.getDefaultCursor().getNextRow(cols));
    }

    private static void doCheckMSISAM2008Db(Database db) throws Exception {
        assertEquals(Database.FileFormat.MSISAM, db.getFileFormat());

        assertEquals(Set.of("ACCT", "ADDR", "ADV", "ADV_SUM", "Advisor Important Dates Custom Pool", "Asset Allocation Custom Pool", "AUTO", "AWD", "BGT", "BGT_BKT", "BGT_ITM", "BILL",
            "BILL_FLD", "CAT", "CESRC", "CLI", "CLI_DAT", "CNTRY", "CRIT", "CRNC", "CRNC_EXCHG", "CT", "DHD", "Feature Expiration Custom Pool", "FI", "Inventory Custom Pool", "ITM", "IVTY", "LOT",
            "LSTEP", "MAIL", "MCSRC", "PAY", "PGM", "PM_RPT", "PMT", "PORT_REC", "Portfolio View Custom Pool", "POS_STMT", "PREF", "PREF_LIST", "PRODUCT", "PROJ", "PROV_FI", "PROV_FI_PAY",
            "Report Custom Pool", "SAV_GOAL", "SCHE_TASK", "SEC", "SEC_SPLIT", "SIC", "SOQ", "SP", "STMT", "SVC", "Tax Rate Custom Pool", "Tax Scenario Custom Pool", "TAXLINE", "TMI", "TRIP", "TRN",
            "TRN_INV", "TRN_INVOICE", "TRN_OL", "TRN_SPLIT", "TRN_XFER", "TXSRC", "UI_VIEW", "UIE", "UNOTE", "VIEW", "Worksheet Custom Pool", "X_FMLA", "X_ITM", "X_META_REF", "X_PARM", "XACCT",
            "XBAG", "XMAPACCT", "XMAPSAT", "XMAPSEC", "XPAY", "XSYNCCHUNK"), db.getTableNames());

        Table t = db.getTable("CRNC");

        Set<String> cols = Set.of("hcrnc", "szName", "lcid", "szIsoCode", "szSymbol");

        assertEquals(createExpectedRow("hcrnc", 1, "szName", "Argentine peso", "lcid", 11274, "szIsoCode", "ARS", "szSymbol", "/ARSUS"), t.getDefaultCursor().getNextRow(cols));

        assertEquals(createExpectedRow("hcrnc", 2, "szName", "Australian dollar", "lcid", 3081, "szIsoCode", "AUD", "szSymbol", "/AUDUS"), t.getDefaultCursor().getNextRow(cols));

        assertEquals(createExpectedRow("hcrnc", 3, "szName", "Austrian schilling", "lcid", 3079, "szIsoCode", "ATS", "szSymbol", "/ATSUS"), t.getDefaultCursor().getNextRow(cols));

        assertEquals(createExpectedRow("hcrnc", 4, "szName", "Belgian franc", "lcid", 2060, "szIsoCode", "BEF", "szSymbol", "/BEFUS"), t.getDefaultCursor().getNextRow(cols));
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
