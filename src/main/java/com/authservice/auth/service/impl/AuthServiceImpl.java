package com.authservice.auth.service.impl;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.authservice.auth.dto.AuthResponse;
import com.authservice.auth.dto.LoginRequest;
import com.authservice.auth.dto.SignupRequest;

import com.authservice.auth.entity.LoginAudit;
import com.authservice.auth.entity.PasswordResetToken;
import com.authservice.auth.entity.User;
import com.authservice.auth.entity.UserSession;

import com.authservice.auth.exception.AccountLockedException;
import com.authservice.auth.exception.InvalidCredentialsException;
import com.authservice.auth.exception.NotFoundException;
import com.authservice.auth.exception.TooManyRequestsException;
import com.authservice.auth.exception.UserAlreadyExistsException;
import com.authservice.auth.exception.InternalServerException;

import com.authservice.auth.repository.LoginAuditRepository;
import com.authservice.auth.repository.PasswordResetTokenRepository;
import com.authservice.auth.repository.UserRepository;
import com.authservice.auth.repository.UserSessionRepository;

import com.authservice.auth.security.JwtUtil;
import com.authservice.auth.security.TokenBlacklistService;

import com.authservice.auth.service.AuthService;
import com.authservice.auth.service.RateLimiterService;

@Service	
public class AuthServiceImpl implements AuthService {

    private static final Logger log =
            LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final LoginAuditRepository loginAuditRepository;
    private final RateLimiterService rateLimiterService;
    private final TokenBlacklistService tokenBlacklistService;
    private final UserSessionRepository userSessionRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;

    public AuthServiceImpl(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            LoginAuditRepository loginAuditRepository,
            RateLimiterService rateLimiterService,
            TokenBlacklistService tokenBlacklistService,
            UserSessionRepository userSessionRepository,
            PasswordResetTokenRepository passwordResetTokenRepository) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.loginAuditRepository = loginAuditRepository;
        this.rateLimiterService = rateLimiterService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.userSessionRepository = userSessionRepository;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
    }

   

    // SIGNUP
    @Override
    public AuthResponse signup(SignupRequest request) {

        log.info("Signup request received | email={}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Signup failed | email already exists={}", request.getEmail());
            throw new UserAlreadyExistsException("Email already exists");
        }

        try {

            User user = new User();
            user.setEmail(request.getEmail());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setRole("ROLE_USER");
            user.setEnabled(true);

            userRepository.save(user);

            log.info("User registered successfully | email={}", user.getEmail());

            return new AuthResponse(null, null);

        } catch (Exception e) {

            log.error("Unexpected signup error | email={}", request.getEmail(), e);
            throw new InternalServerException("Internal server error");
        }
    }

 // LOGIN
    @Override
    public AuthResponse login(LoginRequest request, String ip, String device) {

        String email = request.getEmail();

        log.info("Login request received | email={} | ip={}", email, ip);

        try {

            String key1 = ip + ":" + email;
            String key2 = "GLOBAL:" + email;

            if (!rateLimiterService.tryConsume(key1) ||
                !rateLimiterService.tryConsume(key2)) {

                log.warn("Too many login attempts | email={} | ip={}", email, ip);
                throw new TooManyRequestsException("Too many login attempts");
            }

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> {

                        LoginAudit audit = new LoginAudit();
                        audit.setEmail(email);
                        audit.setSuccess(false);
                        audit.setIp(ip);
                        audit.setCreatedAt(LocalDateTime.now()); // FIX
                        loginAuditRepository.save(audit);

                        log.warn("Login failed | user not found | email={}", email);
                        return new InvalidCredentialsException("Invalid credentials");
                    });

            // FIX: ACCOUNT LOCK CHECK
            if (user.isAccountLocked()) {
                log.warn("Login blocked | account locked | email={}", email);
                throw new AccountLockedException("Account locked");
            }

            // PASSWORD CHECK
            if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {

                user.setFailedAttempts(user.getFailedAttempts() + 1);

                log.warn("Invalid password | email={} | attempts={}",
                        email, user.getFailedAttempts());

                LoginAudit audit = new LoginAudit();
                audit.setEmail(email);
                audit.setSuccess(false);
                audit.setIp(ip);
                audit.setCreatedAt(LocalDateTime.now()); // FIX
                loginAuditRepository.save(audit);

                if (user.getFailedAttempts() >= 5) {

                    user.setAccountLocked(true);
                    userRepository.save(user);

                    log.warn("Account locked | email={} | attempts={}",
                            email, user.getFailedAttempts());

                    throw new AccountLockedException("Account locked");
                }

                userRepository.save(user);

                throw new InvalidCredentialsException("Invalid credentials");
            }

            // RESET FAILED ATTEMPTS
            user.setFailedAttempts(0);
            userRepository.save(user);

            String accessToken =
                    jwtUtil.generateAccessToken(user.getEmail(), user.getRole());

            String refreshToken =
                    jwtUtil.generateRefreshToken(user.getEmail());

            user.setRefreshToken(refreshToken);
            user.setRefreshTokenExpiry(LocalDateTime.now().plusDays(7));

            userRepository.save(user);

            log.info("Tokens generated | email={}", email);

            LoginAudit audit = new LoginAudit();
            audit.setEmail(user.getEmail());
            audit.setSuccess(true);
            audit.setIp(ip);
            audit.setCreatedAt(LocalDateTime.now()); // FIX
            loginAuditRepository.save(audit);

            UserSession session = new UserSession();
            session.setEmail(user.getEmail());
            session.setRefreshToken(refreshToken);
            session.setActive(true);
            session.setCreatedAt(LocalDateTime.now());
            session.setIpAddress(ip);
            session.setDevice(device);

            userSessionRepository.save(session);

            log.info("Session created | email={} | device={}", email, device);

            return new AuthResponse(accessToken, refreshToken);

        } catch (InvalidCredentialsException |
                 TooManyRequestsException |
                 AccountLockedException e) {

            log.warn("Login failed | email={} | reason={}", email, e.getMessage());
            throw e;

        } catch (Exception e) {

            log.error("Unexpected login error | email={}", email, e);
            throw new InternalServerException("Internal server error");
        }
    }
    
    //ReFRESh
    
    @Override
    public AuthResponse refresh(String refreshToken) {

        log.info("Refresh token request received");

        try {

            // BLACKLIST CHECK
            if (tokenBlacklistService.isBlacklisted(refreshToken)) {
                throw new InvalidCredentialsException("Token blacklisted");
            }

            User user = userRepository.findByRefreshToken(refreshToken)
                    .orElseThrow(() ->
                            new InvalidCredentialsException("Invalid refresh token"));

            if (user.getRefreshTokenExpiry().isBefore(LocalDateTime.now())) {

                log.warn("Refresh token expired | email={}", user.getEmail());
                throw new InvalidCredentialsException("Refresh token expired");
            }

            // GENERATE NEW TOKENS (ROTATION)
            String newAccessToken =
                    jwtUtil.generateAccessToken(user.getEmail(), user.getRole());

            String newRefreshToken =
                    jwtUtil.generateRefreshToken(user.getEmail());

            // CALCULATE REMAINING TTL
            long ttl = jwtUtil.getRemainingExpiration(refreshToken);

            // BLACKLIST OLD REFRESH TOKEN
            tokenBlacklistService.blacklist(refreshToken, ttl);

            // SAVE NEW REFRESH TOKEN
            user.setRefreshToken(newRefreshToken);
            user.setRefreshTokenExpiry(LocalDateTime.now().plusDays(7));

            userRepository.save(user);

            log.info("Refresh token rotated | email={}", user.getEmail());

            return new AuthResponse(newAccessToken, newRefreshToken);

        } catch (Exception e) {

            log.error("Refresh token processing error", e);
            throw new InternalServerException("Internal server error");
        }
    }
    
    //logout

    @Override
    public String logout(String refreshToken) {

        log.info("Logout request received");

        try {

            // already blacklisted
            if (tokenBlacklistService.isBlacklisted(refreshToken)) {
                return "Already logged out";
            }

            User user = userRepository.findByRefreshToken(refreshToken)
                    .orElseThrow(() ->
                            new NotFoundException("session not found"));
            

            log.info("Blacklisting refresh token for logout | email={}", user.getEmail());

            // GET REMAINING TOKEN EXPIRY
            long expiry = jwtUtil.getRemainingExpiration(refreshToken);

            // BLACKLIST WITH EXPIRY
            tokenBlacklistService.blacklist(refreshToken, expiry);

            user.setRefreshToken(null);
            user.setRefreshTokenExpiry(null);

            userRepository.save(user);

            log.info("User logged out successfully | email={}", user.getEmail());

            return "Logout successful";

        } catch (Exception e) {

            log.error("Logout error", e);
            throw new InternalServerException("Internal server error");
        }
    }
    // GET SESSIONS
    @Override
    public List<UserSession> getSessions(String email) {

        log.info("Fetching active sessions | email={}", email);

        try {

            return userSessionRepository.findByEmailAndActiveTrue(email);

        } catch (Exception e) {

            log.error("Fetch sessions error | email={}", email, e);
            throw new InternalServerException("Internal server error");
        }
    }

    // LOGOUT DEVICE
    @Override
    public void logoutDevice(String email, Long sessionId) {

        log.info("Logout device request | email={} | sessionId={}", email, sessionId);

        try {

            UserSession session =
                    userSessionRepository.findById(sessionId)
                            .orElseThrow(() ->
                                    new NotFoundException("Session not found "));

            if (!session.getEmail().equals(email)) {

                log.warn("Unauthorized session access | email={} | sessionId={}", email, sessionId);
                throw new InternalServerException("Internal server error");
            }

            session.setActive(false);
            userSessionRepository.save(session);

            log.info("Session terminated | email={} | sessionId={}", email, sessionId);

        } catch (Exception e) {

            log.error("Logout device error | email={} | sessionId={}", email, sessionId, e);
            throw new NotFoundException("Session not found for this user");
        }
    }
    
    // FORGOT PASSWORD
 // @Override
    public String forgotPassword(String email) {

        log.info("Forgot password request | email={}", email);

        try {

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() ->
                            new NotFoundException("User not found"));

            // FIX: delete old tokens
            passwordResetTokenRepository.deleteByEmail(email);

            String token = UUID.randomUUID().toString();

            PasswordResetToken resetToken = new PasswordResetToken();
            resetToken.setEmail(email);
            resetToken.setToken(token);
            resetToken.setExpiry(LocalDateTime.now().plusMinutes(15));

            passwordResetTokenRepository.save(resetToken);

            log.info("Password reset token generated | email={} | token={}", email, token);

            return "Password reset link sent";

        } catch (NotFoundException e) {

            log.warn("Forgot password failed | email={} | reason={}", email, e.getMessage());
            throw e;

        } catch (Exception e) {

            log.error("Forgot password error | email={}", email, e);
            throw new InternalServerException("Internal server error");
        }
    }
    // RESET PASSWORD
    @Override
    public String resetPassword(String email, String token, String newPassword) {

        log.info("Reset password attempt | email={}", email);

        try {

            PasswordResetToken resetToken = passwordResetTokenRepository
                    .findByToken(token)
                    .orElseThrow(() ->
                            new NotFoundException("Invalid reset token"));

            if (!resetToken.getEmail().equals(email)) {

                log.warn("Reset password email mismatch | email={}", email);
                throw new InvalidCredentialsException("Invalid reset request");
            }

            if (resetToken.getExpiry().isBefore(LocalDateTime.now())) {

                log.warn("Reset token expired | email={}", email);
                throw new InvalidCredentialsException("Reset token expired");
            }

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() ->
                            new NotFoundException("User not found"));

            user.setPassword(passwordEncoder.encode(newPassword));

            userRepository.save(user);

            passwordResetTokenRepository.delete(resetToken);

            log.info("Password reset successful | email={}", email);

            return "Password reset successful";

        } catch (NotFoundException | InvalidCredentialsException e) {

            log.warn("Reset password failed | email={} | reason={}", email, e.getMessage());
            throw e;

        } catch (Exception e) {

            log.error("Reset password error | email={}", email, e);
            throw new InternalServerException("Internal server error");
        }
    }
}