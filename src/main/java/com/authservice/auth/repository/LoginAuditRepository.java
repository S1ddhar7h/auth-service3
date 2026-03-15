package com.authservice.auth.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.authservice.auth.entity.LoginAudit;

public interface LoginAuditRepository extends JpaRepository<LoginAudit, Long> {

    Optional<LoginAudit> findTopByEmailOrderByLoginTimeDesc(String email);
    

}