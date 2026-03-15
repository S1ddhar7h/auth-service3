package com.authservice.auth.exception;

import java.time.LocalDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log =
            LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // INVALID CREDENTIALS
    @ExceptionHandler({ InvalidCredentialsException.class, BadCredentialsException.class })
    public ResponseEntity<ApiError> handleInvalidCredentials(Exception ex) {

        log.warn("Invalid credentials: {}", ex.getMessage());

        return new ResponseEntity<>(
                new ApiError(401, ex.getMessage(), LocalDateTime.now()),
                HttpStatus.UNAUTHORIZED);
    }

    // USER ALREADY EXISTS
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiError> handleUserExists(UserAlreadyExistsException ex) {

        log.warn("Signup conflict: {}", ex.getMessage());

        return new ResponseEntity<>(
                new ApiError(409, ex.getMessage(), LocalDateTime.now()),
                HttpStatus.CONFLICT);
    }

    // ACCOUNT LOCKED
    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ApiError> handleAccountLocked(AccountLockedException ex) {

        log.warn("Account locked: {}", ex.getMessage());

        return new ResponseEntity<>(
                new ApiError(423, ex.getMessage(), LocalDateTime.now()),
                HttpStatus.LOCKED);
    }

    // RATE LIMIT
    @ExceptionHandler(TooManyRequestsException.class)
    public ResponseEntity<ApiError> handleRateLimit(TooManyRequestsException ex) {

        log.warn("Rate limit triggered: {}", ex.getMessage());

        return new ResponseEntity<>(
                new ApiError(429, ex.getMessage(), LocalDateTime.now()),
                HttpStatus.TOO_MANY_REQUESTS);
    }

    // VALIDATION ERROR
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex) {

        String error = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(e -> e.getField() + " : " + e.getDefaultMessage())
                .findFirst()
                .orElse("Validation error");

        log.warn("Validation failed: {}", error);

        return new ResponseEntity<>(
                new ApiError(400, error, LocalDateTime.now()),
                HttpStatus.BAD_REQUEST);
    }

    // ACCESS DENIED
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> handleAccessDenied(AccessDeniedException ex) {

        log.warn("Access denied: {}", ex.getMessage());

        return new ResponseEntity<>(
                new ApiError(403, "Access denied", LocalDateTime.now()),
                HttpStatus.FORBIDDEN);
    }
    
 // NOT FOUND
    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ApiError> handleNotFound(NotFoundException ex) {

        log.warn("Resource not found: {}", ex.getMessage());

        return new ResponseEntity<>(
                new ApiError(404, ex.getMessage(), LocalDateTime.now()),
                HttpStatus.NOT_FOUND);
    }

    // INTERNAL SERVER EXCEPTION (Custom)
    @ExceptionHandler(InternalServerException.class)
    public ResponseEntity<ApiError> handleInternalServer(InternalServerException ex) {

        log.error("Internal server error: {}", ex.getMessage());

        return new ResponseEntity<>(
                new ApiError(500, ex.getMessage(), LocalDateTime.now()),
                HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // FINAL FALLBACK
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleGlobal(Exception ex) {

        log.error("Unhandled exception", ex);

        return new ResponseEntity<>(
                new ApiError(500, "Internal server error", LocalDateTime.now()),
                HttpStatus.INTERNAL_SERVER_ERROR);
    }
}