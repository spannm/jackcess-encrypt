/**
 * Contains classes of Jackcess Encrypt, an add-on to the Jackcess library
 * for handling encryption in Microsoft Access database files.
 * <p>
 * The entry point is {@link io.github.spannm.jackcess.encrypt.CryptCodecProvider}, a Jackcess
 * {@code CodecProvider} which is registered on a {@code DatabaseBuilder} (directly or via
 * {@link io.github.spannm.jackcess.encrypt.CryptCodecUtil}) before opening an encrypted database.
 * A password can be supplied up front or lazily through a
 * {@link io.github.spannm.jackcess.encrypt.PasswordCallback} or any
 * {@link java.util.function.Supplier}, which is only consulted if the database actually requires
 * one.  Problems are reported as
 * {@link io.github.spannm.jackcess.encrypt.InvalidCredentialsException} or
 * {@link io.github.spannm.jackcess.encrypt.InvalidCryptoConfigurationException}.
 */
package io.github.spannm.jackcess.encrypt;
