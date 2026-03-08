package com.authservice.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.authservice.auth.entity.UserSession;
import java.util.List;

public interface UserSessionRepository
extends JpaRepository<UserSession, Long> {

List<UserSession> findByEmailAndActiveTrue(String email);

}