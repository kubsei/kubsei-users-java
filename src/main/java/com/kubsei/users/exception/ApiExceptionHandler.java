package com.kubsei.users.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Validation and other framework errors become ProblemDetail via spring.mvc.problemdetails.enabled.
 * Our own errors add a "code" property: the frontend translates it, "detail" stays for logs and developers.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    public ProblemDetail unauthorized(AuthenticationException ex) {
        return problem(HttpStatus.UNAUTHORIZED, ex.getMessage(), ex.getCode());
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ProblemDetail invalidToken(InvalidTokenException ex) {
        return problem(HttpStatus.UNAUTHORIZED, ex.getMessage(), "SESSION_EXPIRED");
    }

    @ExceptionHandler(InvalidRequestException.class)
    public ProblemDetail badRequest(InvalidRequestException ex) {
        return problem(HttpStatus.BAD_REQUEST, ex.getMessage(), ex.getCode());
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ProblemDetail conflict(UserAlreadyExistsException ex) {
        return problem(HttpStatus.CONFLICT, ex.getMessage(), "EMAIL_TAKEN");
    }

    private static ProblemDetail problem(HttpStatus status, String detail, String code) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setProperty("code", code);
        return problem;
    }
}
