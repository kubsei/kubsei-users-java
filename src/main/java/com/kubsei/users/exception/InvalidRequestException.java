package com.kubsei.users.exception;

/** A request the contract cannot express as validation (e.g. password longer than 72 bytes): 400 with a code. */
public class InvalidRequestException extends RuntimeException {

    private final String code;

    public InvalidRequestException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
