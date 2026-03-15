package com.authservice.auth.controller;

import java.util.List;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import com.authservice.auth.dto.*;
import com.authservice.auth.entity.UserSession;
import com.authservice.auth.service.AuthService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

@Tag(
    name = "Authentication API",
    description = "Endpoints for user signup, login, JWT refresh, password reset, session management and logout."
)
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService s;

    public AuthController(AuthService s) {
        this.s = s;
    }

    @Operation(summary = "User Signup", description = "Register a new user account")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "User created successfully"),
        @ApiResponse(responseCode = "400", description = "Validation error"),
        @ApiResponse(responseCode = "409", description = "User already exists")
    })
    @PostMapping("/signup")
    public AuthResponse signup(@Valid @RequestBody SignupRequest r){
        return s.signup(r);
    }

    @Operation(summary = "User Login", description = "Authenticate user and generate JWT tokens")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Login successful"),
        @ApiResponse(responseCode = "401", description = "Invalid credentials"),
        @ApiResponse(responseCode = "403", description = "Account disabled or locked")
    })
    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest r, HttpServletRequest req){
        return s.login(r, req.getRemoteAddr(), req.getHeader("User-Agent"));
    }

    @Operation(summary = "Refresh Access Token")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "New access token generated"),
        @ApiResponse(responseCode = "401", description = "Invalid refresh token")
    })
    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestBody RefreshRequest r){
        return s.refresh(r.getRefreshToken());
    }

    @Operation(summary = "Forgot Password")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Password reset email sent"),
        @ApiResponse(responseCode = "404", description = "Email not found")
    })
    @PostMapping("/forgot-password")
    public String forgot(@RequestBody ForgotPasswordRequest r){
        return s.forgotPassword(r.getEmail());
    }
    @Operation(summary = "Reset Password")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Password reset successful"),
        @ApiResponse(responseCode = "400", description = "Invalid reset token"),
        @ApiResponse(responseCode = "404", description = "User not found")
    })
    @PostMapping("/reset-password")
    public void reset(@RequestBody ResetPasswordRequest r){
        s.resetPassword(r.getEmail(), r.getToken(), r.getNewPassword());
    }

    @Operation(summary = "Secure Test Endpoint", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Authorized access"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/secure")
    public String secure(){
        return "SECURED API WORKING";
    }

    
    @Operation(summary = "Get Active Sessions", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Sessions fetched"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/sessions")
    public List<UserSession> sessions(Authentication a){
        return s.getSessions(a.getName());
    }

    @Operation(summary = "Logout Specific Device", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Device session terminated"),
        @ApiResponse(responseCode = "404", description = "Session not found"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PostMapping("/logout-device")
    public void logoutDevice(Authentication a, @RequestParam Long sessionId){
        s.logoutDevice(a.getName(), sessionId);
    }

    @Operation(summary = "Logout User", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "User logged out"),
        @ApiResponse(responseCode = "401", description = "Invalid refresh token")
    })
    @PostMapping("/logout")
    public void logout(@RequestBody LogoutRequest r){
        s.logout(r.getRefreshToken());
    }
    
    
}