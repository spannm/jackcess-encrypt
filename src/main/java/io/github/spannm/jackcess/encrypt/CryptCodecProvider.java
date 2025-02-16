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

    public CryptCodecProvider() {
        this(null, null);
    }

    public CryptCodecProvider(String _password) {
        this(_password, null);
    }

    public CryptCodecProvider(PasswordCallback _callback) {
        this(null, _callback);
    }

    public CryptCodecProvider(Supplier<String> _callback) {
        this(null, _callback);
    }

    protected CryptCodecProvider(String _password, Supplier<String> _callback) {
        password = _password;
        callback = _callback;
    }

    @Override
    public String getPassword() {
        return password;
    }

    public void setPassword(String _newPassword) {
        password = _newPassword;
    }

    public PasswordCallback getPasswordCallback() {
        return (PasswordCallback) getPasswordSupplier();
    }

    public Supplier<String> getPasswordSupplier() {
        return callback;
    }

    public void setPasswordCallback(PasswordCallback newCallback) {
        setPasswordSupplier(newCallback);
    }

    public void setPasswordSupplier(Supplier<String> newCallback) {
        callback = newCallback;
    }

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
