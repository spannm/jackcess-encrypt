package io.github.spannm.jackcess.encrypt;

/**
 * Thrown when the wrong credentials (password) has been provided for opening a database.
 */
public class InvalidCredentialsException extends IllegalStateException {
    private static final long serialVersionUID = 20170130L;

    public InvalidCredentialsException(String msg) {
        super(msg);
    }

}
