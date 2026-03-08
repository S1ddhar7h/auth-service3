package com.authservice.auth.repository;

  
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.authservice.auth.entity.PasswordResetToken;

public interface PasswordResetTokenRepository
        extends JpaRepository<PasswordResetToken, Long> {

    Optional<PasswordResetToken> findByToken(String token);
}