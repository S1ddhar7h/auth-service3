package com.authservice.auth.controller;
import jakarta.servlet.http.HttpServletRequest;
import com.authservice.auth.dto.*;
import com.authservice.auth.entity.User;
import com.authservice.auth.repository.UserRepository;
import com.authservice.auth.service.AuthService;
import java.util.List;
import com.authservice.auth.repository.UserSessionRepository;
import com.authservice.auth.entity.UserSession;
//import java.util.List;
//import org.springframework.security.core.Authentication;

import java.util.Map;

import org.springframework.security.core.Authentication;
//import com.sun.org.slf4j.internal.LoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//import ch.qos.logback.classic.Logger;
import io.swagger.v3.oas.annotations.tags.Tag;
//import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import com.authservice.auth.dto.LogoutRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@Tag(name = "Authentication API", description = "Signup, Login, Refresh, Logout")
@RestController
@RequestMapping("/auth")
public class AuthController {
	private static final Logger log =
	       LoggerFactory.getLogger(AuthController.class);


    private final AuthService authService;
    private final UserRepository userRepository;
    private final UserSessionRepository userSessionRepository;

    public AuthController(AuthService authService,
                          UserRepository userRepository, 
                                  UserSessionRepository userSessionRepository) {

                this.authService = authService;
                this.userRepository = userRepository;
                this.userSessionRepository = userSessionRepository;
            } {
            }

    // SIGNUP
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<AuthResponse>> signup(
            @Valid @RequestBody SignupRequest request) {

        AuthResponse response = authService.signup(request);

        return ResponseEntity.ok(
                new ApiResponse<>(200, "Signup successful", response)
        );
    }

    // LOGIN
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        String ip = httpRequest.getRemoteAddr();

        AuthResponse response = authService.login(request, ip);

        return ResponseEntity.ok(
                new ApiResponse<>(200, "Login successful", response)
        );
    }

    // SECURE API
    @GetMapping("/secure")
    public ResponseEntity<ApiResponse<String>> secureApi() {

        return ResponseEntity.ok(
                new ApiResponse<>(200, "Success", "SECURED API WORKING")
        );
    }

    // EMAIL VERIFY
    @GetMapping("/verify")
    public String verifyEmail(@RequestParam String token) {

        System.out.println("Token received: " + token);

        User user = userRepository.findByVerificationToken(token)
                .orElseThrow(() ->
                        new RuntimeException("Invalid token"));

        System.out.println("User found: " + user.getEmail());

        user.setEnabled(true);
        user.setVerificationToken(null);

        userRepository.save(user);

        return "Email verified successfully";
        
    }
    
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(
            @RequestBody java.util.Map<String,String> request) {

        String refreshToken = request.get("refreshToken");

        AuthResponse response = authService.refresh(refreshToken);

        return ResponseEntity.ok(
                new ApiResponse<>(200, "Token refreshed", response)
        );
    }
    @PostMapping("/logout")
    
    public ResponseEntity<ApiResponse<Boolean>> logout(@RequestBody LogoutRequest request) {

        authService.logout(request.getRefreshToken());

        return ResponseEntity.ok(
            new ApiResponse<>(200, "Logout successful", true)
        );
    }
    
    @PostMapping("/forgot-password")
    public String forgotPassword(@RequestBody Map<String,String> request) {
        return authService.forgotPassword(request.get("email"));
    }

    @PostMapping("/reset-password")
    public String resetPassword(@RequestBody ResetPasswordRequest request) {
        return authService.resetPassword(
            request.getToken(),
            request.getNewPassword()
        );
    }
    
   // -----------------SESSIONS-----------------------------
    
    @GetMapping("/sessions")
    public List<UserSession> getSessions(Authentication auth){

        String email = auth.getName();

        return userSessionRepository.findByEmailAndActiveTrue(email);
    }
    
    //---------------------LOGOUT DEVICE--------------------------
    
    @PostMapping("/logout-device")
    public String logoutDevice(@RequestParam Long sessionId){

        UserSession session =
            userSessionRepository.findById(sessionId)
            .orElseThrow();

        session.setActive(false);

        userSessionRepository.save(session);

        return "Session terminated";
    }
    }
