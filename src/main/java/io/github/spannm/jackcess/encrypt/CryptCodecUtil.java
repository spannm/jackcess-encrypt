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
     */
    public static DatabaseBuilder withCodecProvider(DatabaseBuilder _dbb) {
        return _dbb.withCodecProvider(new CryptCodecProvider());
    }

    /**
     * Configures a new CryptCodecProvider with the given password on the given DatabaseBuilder.
     */
    public static DatabaseBuilder withCodecProvider(DatabaseBuilder _dbb, String _password) {
        return _dbb.withCodecProvider(new CryptCodecProvider(_password));
    }

}
