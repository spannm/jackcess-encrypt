package io.github.spannm.jackcess.encrypt;

import io.github.spannm.jackcess.JackcessRuntimeException;
import io.github.spannm.jackcess.encrypt.impl.JetCryptCodecHandler;
import io.github.spannm.jackcess.encrypt.impl.MSISAMCryptCodecHandler;
import io.github.spannm.jackcess.encrypt.impl.OfficeCryptCodecHandler;
import io.github.spannm.jackcess.impl.*;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.function.Supplier;

/**
 * Implementation of CodecProvider with support for some forms of Microsoft
 * Access and Microsoft Money file encryption.
 *
 * <p>Note, not all "encrypted" access databases actually require passwords in
 * order to be opened.  Many older forms of access "encryption" ("obfuscation"
 * would be a better term) include the keys within the access file itself.  If
 * required, a password can be provided in one of two ways:</p>
 *
 * <ul>
 * <li>If a {@link PasswordCallback} or {@link Supplier} has been provided
 *     (via the constructor or {@link #setPasswordCallback}), then
 *     {@link PasswordCallback#getPassword} will be invoked to retrieve the
 *     necessary password</li>
 * <li>If no password callback has been configured, then {@link #getPassword}
 *     will be invoked directly on the CryptCodecProvider (which will return
 *     the password configured via the constructor or {@link
 *     #setPassword})</li>
 * </ul>
 *
 * @author Vladimir Berezniker
 */
public class CryptCodecProvider implements CodecProvider, PasswordCallback {
    private String           password;
    private Supplier<String> callback;

    /**
     * Creates a new provider with no password and no password callback.
     */
    public CryptCodecProvider() {
        this(null, null);
    }

    /**
     * Creates a new provider with the given password.
     *
     * @param _password the password to use when opening an encrypted database, may be {@code null}
     */
    public CryptCodecProvider(String _password) {
        this(_password, null);
    }

    /**
     * Creates a new provider which retrieves the password from the given callback on demand.
     *
     * @param _callback the callback invoked when a password is actually required, may be {@code null}
     */
    public CryptCodecProvider(PasswordCallback _callback) {
        this(null, _callback);
    }

    /**
     * Creates a new provider which retrieves the password from the given supplier on demand.
     *
     * @param _callback the supplier invoked when a password is actually required, may be {@code null}
     */
    public CryptCodecProvider(Supplier<String> _callback) {
        this(null, _callback);
    }

    /**
     * Creates a new provider with the given password and password supplier.
     *
     * @param _password the password to use when opening an encrypted database, may be {@code null}
     * @param _callback the supplier invoked when a password is actually required, may be {@code null}
     */
    protected CryptCodecProvider(String _password, Supplier<String> _callback) {
        password = _password;
        callback = _callback;
    }

    /**
     * Returns the password configured on this provider.  This method is only
     * invoked if no password callback has been configured.
     *
     * @return the configured password, may be {@code null}
     */
    @Override
    public String getPassword() {
        return password;
    }

    /**
     * Sets the password used when opening an encrypted database.
     *
     * @param _newPassword the new password, may be {@code null}
     */
    public void setPassword(String _newPassword) {
        password = _newPassword;
    }

    /**
     * Returns the configured password callback.
     *
     * @return the configured password callback, may be {@code null}
     * @throws ClassCastException if the configured password supplier is not a {@link PasswordCallback}
     */
    public PasswordCallback getPasswordCallback() {
        return (PasswordCallback) getPasswordSupplier();
    }

    /**
     * Returns the configured password supplier.
     *
     * @return the configured password supplier, may be {@code null}
     */
    public Supplier<String> getPasswordSupplier() {
        return callback;
    }

    /**
     * Sets the callback invoked when a password is actually required.
     *
     * @param newCallback the new password callback, may be {@code null}
     */
    public void setPasswordCallback(PasswordCallback newCallback) {
        setPasswordSupplier(newCallback);
    }

    /**
     * Sets the supplier invoked when a password is actually required.
     *
     * @param newCallback the new password supplier, may be {@code null}
     */
    public void setPasswordSupplier(Supplier<String> newCallback) {
        callback = newCallback;
    }

    /**
     * Creates a codec handler matching the encryption used by the given database
     * page channel.  A password is only retrieved (from the configured password
     * supplier, or from this provider itself) if the database format actually
     * requires one.
     *
     * @param channel the page channel of the database being opened
     * @param charset the charset of the database being opened
     * @return a handler for the encryption of the given database, never {@code null}
     * @throws IOException if an I/O error occurs while reading the encryption information
     * @throws JackcessRuntimeException if the database uses an unknown codec type
     * @throws InvalidCredentialsException if the configured password is not valid for the database
     * @throws InvalidCryptoConfigurationException if the crypto configuration of the database is invalid
     */
    @Override
    public CodecHandler createHandler(PageChannel channel, Charset charset) throws IOException {
        // determine from where to retrieve the password
        Supplier<String> lcallback = getPasswordSupplier();
        if (lcallback == null) {
            lcallback = this;
        }

        JetFormat format = channel.getFormat();
        switch (format.CODEC_TYPE) {
            case NONE:
                // no encoding, all good
                return DefaultCodecProvider.DUMMY_HANDLER;

            case JET:
                return JetCryptCodecHandler.create(channel);

            case MSISAM:
                return MSISAMCryptCodecHandler.create(lcallback, channel, charset);

            case OFFICE:
                return OfficeCryptCodecHandler.create(lcallback, channel, charset);

            default:
                throw new JackcessRuntimeException("Unknown codec type " + format.CODEC_TYPE);
        }
    }
}
