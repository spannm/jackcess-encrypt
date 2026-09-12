/**
 * Small compatibility layer over the Bouncy Castle stream cipher API.
 * <p>
 * Bouncy Castle 1.51 made a binary incompatible change to its {@code StreamCipher} interface.
 * {@link io.github.spannm.jackcess.encrypt.util.StreamCipherCompat} mirrors that interface in a
 * version neutral way, {@link io.github.spannm.jackcess.encrypt.util.StreamCipherFactory} selects
 * and loads a matching implementation at runtime, and
 * {@link io.github.spannm.jackcess.encrypt.util.RC4EngineCompat} adapts the Bouncy Castle
 * {@code RC4Engine} to it.
 * <p>
 * The RC4 based codec handlers of this library obtain their cipher instances exclusively through
 * {@link io.github.spannm.jackcess.encrypt.util.StreamCipherFactory#newRC4Engine()}.
 */
package io.github.spannm.jackcess.encrypt.util;
