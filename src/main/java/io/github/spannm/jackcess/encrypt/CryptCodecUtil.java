package io.github.spannm.jackcess.encrypt;

import io.github.spannm.jackcess.DatabaseBuilder;

/**
 * Utility class for configuring the {@link CryptCodecProvider} on the given
 * {@link DatabaseBuilder}.
 */
public final class CryptCodecUtil {

    private CryptCodecUtil() {
    }

    /**
     * Configures a new CryptCodecProvider on the given DatabaseBuilder.
     *
     * @param _dbb the database builder to configure
     * @return the given database builder
     */
    public static DatabaseBuilder withCodecProvider(DatabaseBuilder _dbb) {
        return _dbb.withCodecProvider(new CryptCodecProvider());
    }

    /**
     * Configures a new CryptCodecProvider with the given password on the given DatabaseBuilder.
     *
     * @param _dbb the database builder to configure
     * @param _password the password used to open the database, may be {@code null}
     * @return the given database builder
     */
    public static DatabaseBuilder withCodecProvider(DatabaseBuilder _dbb, String _password) {
        return _dbb.withCodecProvider(new CryptCodecProvider(_password));
    }

}
