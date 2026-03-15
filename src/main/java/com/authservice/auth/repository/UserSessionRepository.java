package com.authservice.auth.repository;

 
import java.util.List;
import java.util.Optional;


import org.springframework.data.jpa.repository.JpaRepository;
import com.authservice.auth.entity.UserSession;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    Optional<UserSession> findByRefreshToken(String refreshToken);

	List<UserSession> findByEmailAndActiveTrue(String email);

}