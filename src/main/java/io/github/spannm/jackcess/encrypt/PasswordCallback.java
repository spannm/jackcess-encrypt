package io.github.spannm.jackcess.encrypt;

import java.util.function.Supplier;

/**
 * Callback which can be used by CryptCodecProvider to retrieve a password on
 * demand, at the time it is required.  The callback will only be invoked if
 * it is determined that a file <i>actually</i> requires a password to be
 * opened.  This could be used to implement a password user prompt utility.
 *
 * Note, CryptCodecProvider now accepts a {@link Supplier} as the password
 * callback, so this interface is no longer necessary (kept for historical
 * compatibility).
 */
@FunctionalInterface
public interface PasswordCallback extends Supplier<String> {
    /**
     * Invoked by CryptCodecProvider when a password is necessary to open an access database.
     *
     * @return the required password
     */
    String getPassword();

    @Override
    default String get() {
        return getPassword();
    }
}
