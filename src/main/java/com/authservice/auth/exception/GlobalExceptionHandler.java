package com.authservice.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log =
            LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiError> handleInvalidCredentials(
            InvalidCredentialsException ex) {

        return new ResponseEntity<ApiError>(
                new ApiError(401, ex.getMessage()),
                HttpStatus.UNAUTHORIZED
        );
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiError> handleUserExists(
            UserAlreadyExistsException ex) {

        return new ResponseEntity<ApiError>(
                new ApiError(409, ex.getMessage()),
                HttpStatus.CONFLICT
        );
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ApiError> handleAccountLocked(
            AccountLockedException ex) {

        return new ResponseEntity<ApiError>(
                new ApiError(423, ex.getMessage()),
                HttpStatus.LOCKED
        );
    }

    @ExceptionHandler(TooManyRequestsException.class)
    public ResponseEntity<ApiError> handleRateLimit(
            TooManyRequestsException ex) {

        return new ResponseEntity<ApiError>(
                new ApiError(429, ex.getMessage()),
                HttpStatus.TOO_MANY_REQUESTS
        );
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiError> handleGeneric(
            RuntimeException ex) {

        ex.printStackTrace();   // <-- यह line add करो

        return new ResponseEntity<ApiError>(
                new ApiError(400, ex.getMessage()),
                HttpStatus.BAD_REQUEST
        );
    }
    }
