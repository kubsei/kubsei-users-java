package com.kubsei.users.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Validation and other framework errors become ProblemDetail via spring.mvc.problemdetails.enabled. */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler({AuthenticationException.class, InvalidTokenException.class})
    public ProblemDetail unauthorized(RuntimeException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ProblemDetail conflict(UserAlreadyExistsException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
    }
}
