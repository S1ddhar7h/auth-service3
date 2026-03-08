package com.authservice.auth.service;
import com.authservice.auth.repository.PasswordResetTokenRepository;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;


import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.authservice.auth.exception.TooManyRequestsException;
import com.authservice.auth.entity.UserSession;
import com.authservice.auth.repository.UserSessionRepository;

import com.authservice.auth.dto.AuthResponse;
import com.authservice.auth.dto.LoginRequest;
import com.authservice.auth.dto.SignupRequest;
import com.authservice.auth.entity.LoginAudit;
import com.authservice.auth.entity.PasswordResetToken;
import com.authservice.auth.entity.User;
import com.authservice.auth.exception.InvalidCredentialsException;
import com.authservice.auth.exception.UserAlreadyExistsException;
import com.authservice.auth.repository.LoginAuditRepository;
//import com.authservice.auth.repository.PasswordResetTokenRepository;
import com.authservice.auth.repository.UserRepository;
import com.authservice.auth.security.JwtUtil;
import com.authservice.auth.security.TokenBlacklistService;
@Service
public class AuthService {

    private static final Logger log =
            LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final LoginAuditRepository loginAuditRepository;
    private final RateLimiterService rateLimiterService;
    private final EmailService emailService;
    private final TokenBlacklistService tokenBlacklistService;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final UserSessionRepository userSessionRepository;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            LoginAuditRepository loginAuditRepository,
            RateLimiterService rateLimiterService,
            EmailService emailService,
            TokenBlacklistService tokenBlacklistService,
            PasswordResetTokenRepository passwordResetTokenRepository,
            UserSessionRepository userSessionRepository) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.loginAuditRepository = loginAuditRepository;
        this.rateLimiterService = rateLimiterService;
        this.emailService = emailService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.userSessionRepository = userSessionRepository;
    }



    // ---------------- SIGNUP ----------------
   
    public AuthResponse signup(SignupRequest request) {
    	 log.info("Signup request received for email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Email already exists");
        }

        User user = new User();
        

        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole("ROLE_USER");

        String verificationToken = UUID.randomUUID().toString();

        user.setVerificationToken(verificationToken);
        //user.setVerificationTokenExpiry(LocalDateTime.now().plusHours(24));
        user.setEnabled(true);

        userRepository.save(user);
        log.info("User created successfully: {}", user.getEmail());

       // emailService.sendVerificationEmail(user.getEmail(), verificationToken);

        return new AuthResponse(null, null);
    }

    // ---------------- LOGIN ----------------

    public AuthResponse login(LoginRequest request, String ip) {

    	System.out.println("CLIENT IP = " + ip);

    	String email = request.getEmail();

    	log.info("Login attempt for email: {}", email);

    	// IP based rate limiter
    	String key1 = ip + ":" + email;

    	// global account limiter
    	String key2 = "GLOBAL:" + email;

    	if (!rateLimiterService.tryConsume(key1) ||
    	    !rateLimiterService.tryConsume(key2)) {

    	    log.warn("Too many login attempts for email {}", email);
    	    throw new TooManyRequestsException("Too many login attempts");
    	}

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> {
                    log.warn("Login failed. User not found: {}", request.getEmail());
                    return new InvalidCredentialsException("Invalid credentials");
                });

        if (!user.isEnabled()) {
            log.warn("Login blocked. Email not verified: {}", request.getEmail());
            throw new RuntimeException("Please verify your email first");
        }

        if (user.isAccountLocked()) {

            log.error("Account locked for email: {}", user.getEmail());

            LoginAudit audit = new LoginAudit();
            audit.setEmail(user.getEmail());
            audit.setSuccess(false);
            audit.setIp(ip);
            loginAuditRepository.save(audit);

            throw new RuntimeException("Account locked due to many failed attempts");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {

            log.warn("Login failed. Wrong password for email: {}", request.getEmail());

            user.setFailedAttempts(user.getFailedAttempts() + 1);

            if (user.getFailedAttempts() >= 5) {
                user.setAccountLocked(true);
                log.error("Account locked after multiple failed attempts: {}", user.getEmail());
            }

            userRepository.save(user);

            LoginAudit audit = new LoginAudit();
            audit.setEmail(user.getEmail());
            audit.setSuccess(false);
            audit.setIp(ip);
            loginAuditRepository.save(audit);

            throw new InvalidCredentialsException("Invalid credentials");
        }

        // successful login
        user.setFailedAttempts(0);
        userRepository.save(user);

        log.info("Login successful for user: {}", user.getEmail());

        Optional<LoginAudit> lastLogin =
                loginAuditRepository.findTopByEmailOrderByLoginTimeDesc(user.getEmail());

        if (lastLogin.isPresent() && !lastLogin.get().getIp().equals(ip)) {
            log.warn("Suspicious login detected for {}", user.getEmail());
        }

        LoginAudit audit = new LoginAudit();
        audit.setEmail(user.getEmail());
        audit.setSuccess(true);
        audit.setIp(ip);
        loginAuditRepository.save(audit);

        String accessToken = jwtUtil.generateAccessToken(
                user.getEmail(),
                user.getRole());

        String refreshToken = jwtUtil.generateRefreshToken(
                user.getEmail());

        user.setRefreshToken(refreshToken);
        user.setRefreshTokenExpiry(LocalDateTime.now().plusDays(7));

        userRepository.save(user);

        return new AuthResponse(accessToken, refreshToken);
    }
    // ---------------- REFRESH TOKEN ----------------
    public AuthResponse refresh(String refreshToken) {

        User user = userRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (user.getRefreshTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Refresh token expired");
        }

        // ROTATION: generate new refresh token
        String newRefreshToken = jwtUtil.generateRefreshToken(user.getEmail());

        user.setRefreshToken(newRefreshToken);
        user.setRefreshTokenExpiry(LocalDateTime.now().plusDays(7));

        userRepository.save(user);

        String newAccessToken = jwtUtil.generateAccessToken(
                user.getEmail(),
                user.getRole()
        );

        return new AuthResponse(newAccessToken, newRefreshToken);
    }
    // ---------------- LOGOUT ----------------

    public String logout(String refreshToken) {

        User user = userRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("User not found"));

        tokenBlacklistService.blacklist(refreshToken);

        user.setRefreshToken(null);
        user.setRefreshTokenExpiry(null);

        userRepository.save(user);

        return "Logout successful";
    }
    
  //--------------PASSWORD FORGET-------------
    public String forgotPassword(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // raw token generate
        String rawToken = UUID.randomUUID().toString();

        // hash token before saving
        String hashedToken = passwordEncoder.encode(rawToken);

        PasswordResetToken reset = new PasswordResetToken();
        reset.setEmail(email);
        reset.setToken(hashedToken);
        reset.setExpiry(LocalDateTime.now().plusMinutes(15));

        passwordResetTokenRepository.save(reset);

        // user को raw token ही भेजेंगे
        emailService.sendPasswordResetEmail(email, rawToken);

        return "Password reset link sent";
    
    }
    //------------PASSWORD RESET--------------------
    public String resetPassword(String token, String newPassword) {

        PasswordResetToken reset = passwordResetTokenRepository
                .findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        // expiry check
        if (reset.getExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Token expired");
        }

        User user = userRepository.findByEmail(reset.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // token delete after use
        passwordResetTokenRepository.delete(reset);

        return "Password reset successful";
    }
}