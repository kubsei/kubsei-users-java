package com.kubsei.users.exception;

/** code: stable value the frontend translates (INVALID_CREDENTIALS, USE_PROVIDER, ACCOUNT_DISABLED, TOO_MANY_ATTEMPTS). */
public class AuthenticationException extends RuntimeException {

    private final String code;

    public AuthenticationException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
