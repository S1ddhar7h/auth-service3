package com.authservice.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
public class LoginAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email;

    private boolean success;

    private String ip;

    private LocalDateTime loginTime = LocalDateTime.now();

    public LoginAudit() {}

    public Long getId() {
    	
        return id;
    }

    public String getEmail() {
        return email;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getIp() {
        return ip;
    }

    public LocalDateTime getLoginTime() {
        return loginTime;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

	public void setCreatedAt(LocalDateTime now) {
		// TODO Auto-generated method stub
		
	}

	public void setLoginTime(LocalDateTime loginTime) {
		this.loginTime = loginTime;
	}
}