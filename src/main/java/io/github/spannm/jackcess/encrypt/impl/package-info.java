/**
 * Internal implementations of the Jackcess {@code CodecHandler} interface, one per family of
 * Access/Money file encoding.
 * <p>
 * {@link io.github.spannm.jackcess.encrypt.impl.BaseCryptCodecHandler} provides the shared
 * page encryption/decryption plumbing (cipher setup, hashing, key/page-number mixing) on top of
 * which {@link io.github.spannm.jackcess.encrypt.impl.JetCryptCodecHandler} (classic Jet RC4
 * obfuscation), {@link io.github.spannm.jackcess.encrypt.impl.MSISAMCryptCodecHandler} (Microsoft
 * Money) and {@link io.github.spannm.jackcess.encrypt.impl.OfficeCryptCodecHandler} (Office
 * Document Cryptography, see {@link io.github.spannm.jackcess.encrypt.impl.office}) are built.
 * {@link io.github.spannm.jackcess.encrypt.impl.KeyCache} keeps the most recently computed
 * per-page cipher parameters around, since keys are derived per database page.
 * <p>
 * These classes are instantiated by
 * {@link io.github.spannm.jackcess.encrypt.CryptCodecProvider} and are not part of the public API;
 * they may change without notice.
 */
package io.github.spannm.jackcess.encrypt.impl;
