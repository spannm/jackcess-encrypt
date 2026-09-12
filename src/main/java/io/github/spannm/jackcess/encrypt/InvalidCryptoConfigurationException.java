package io.github.spannm.jackcess.encrypt;

/**
 * Thrown when the crypto configuration contained within the database is invalid.
 */
public class InvalidCryptoConfigurationException extends IllegalStateException {
    private static final long serialVersionUID = 20170130L;

    /**
     * Creates a new exception with the given message.
     *
     * @param msg the detail message
     */
    public InvalidCryptoConfigurationException(String msg) {
        super(msg);
    }

    /**
     * Creates a new exception with the given message and cause.
     *
     * @param msg the detail message
     * @param t the underlying cause
     */
    public InvalidCryptoConfigurationException(String msg, Throwable t) {
        super(msg, t);
    }
}
