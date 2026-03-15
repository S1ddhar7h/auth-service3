package com.authservice.auth.service;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @SuppressWarnings("unused")
	private final JavaMailSender mailSender;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendVerificationEmail(String email, String token) {

        String link = "http://localhost:8081/auth/verify?token=" + token;

        System.out.println("EMAIL VERIFY LINK:");
        System.out.println(link);
    }

    
    public void sendPasswordResetEmail(String email, String token) {

        String link = "http://localhost:8081/auth/reset-password?token=" + token;

        System.out.println("PASSWORD RESET LINK:");
        System.out.println(link);
    }
}