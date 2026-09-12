/**
 * Implementations of the encryption schemes defined by the MS-OFFCRYPTO "Office Document
 * Cryptography Structure" specification, as used by newer Access database files.
 * <p>
 * {@link io.github.spannm.jackcess.encrypt.impl.office.BlockCipherProvider} and
 * {@link io.github.spannm.jackcess.encrypt.impl.office.StreamCipherProvider} specialize
 * {@link io.github.spannm.jackcess.encrypt.impl.OfficeCryptCodecHandler} for block and stream
 * ciphers respectively. The concrete providers are
 * {@link io.github.spannm.jackcess.encrypt.impl.office.AgileEncryptionProvider} (agile
 * encryption), {@link io.github.spannm.jackcess.encrypt.impl.office.ECMAStandardEncryptionProvider}
 * and its {@link io.github.spannm.jackcess.encrypt.impl.office.NonStandardEncryptionProvider}
 * variant (ECMA-376 standard AES encryption),
 * {@link io.github.spannm.jackcess.encrypt.impl.office.RC4CryptoAPIProvider} (RC4 CryptoAPI) and
 * {@link io.github.spannm.jackcess.encrypt.impl.office.OfficeBinaryDocRC4Provider} (binary document
 * RC4).
 * <p>
 * {@link io.github.spannm.jackcess.encrypt.impl.office.EncryptionHeader} and
 * {@link io.github.spannm.jackcess.encrypt.impl.office.EncryptionVerifier} read the binary
 * encryption structures, while
 * {@link io.github.spannm.jackcess.encrypt.impl.office.XmlEncryptionParser} and
 * {@link io.github.spannm.jackcess.encrypt.impl.office.XmlEncryptionDescriptor} read the xml
 * encryption descriptor of agile encryption and map its algorithm names onto Bouncy Castle
 * digests and ciphers.
 * <p>
 * The {@code // OC: x.y.z} comments throughout this package refer to section numbers of the
 * MS-OFFCRYPTO specification. These classes are internal and may change without notice.
 */
package io.github.spannm.jackcess.encrypt.impl.office;
