package com.authservice.auth.service;
import com.authservice.auth.service.AuthService;
import java.util.List;

import com.authservice.auth.dto.AuthResponse;
import com.authservice.auth.dto.LoginRequest;
import com.authservice.auth.dto.SignupRequest;
import com.authservice.auth.entity.UserSession;

public interface AuthService {

    AuthResponse signup(SignupRequest request);

    AuthResponse login(LoginRequest request, String ip, String device);

    AuthResponse refresh(String refreshToken);

    String logout(String refreshToken);

    String forgotPassword(String email);

    String resetPassword(String email, String token, String newPassword);

    List<UserSession> getSessions(String email);

    void logoutDevice(String email, Long sessionId);
}