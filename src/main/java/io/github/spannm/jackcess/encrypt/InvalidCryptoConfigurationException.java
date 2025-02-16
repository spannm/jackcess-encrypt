package io.github.spannm.jackcess.encrypt;

/**
 * Thrown when the crypto configuration contained within the database is invalid.
 */
public class InvalidCryptoConfigurationException extends IllegalStateException {
    private static final long serialVersionUID = 20170130L;

    public InvalidCryptoConfigurationException(String msg) {
        super(msg);
    }

    public InvalidCryptoConfigurationException(String msg, Throwable t) {
        super(msg, t);
    }
}
