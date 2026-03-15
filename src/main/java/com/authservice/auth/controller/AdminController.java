package com.authservice.auth.controller;

import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.authservice.auth.entity.LoginAudit;
import com.authservice.auth.repository.LoginAuditRepository;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

@Tag(
    name = "Admin APIs",
    description = "Admin operations for monitoring and auditing"
)
@RestController
@RequestMapping("/admin")
public class AdminController {

    private final LoginAuditRepository loginAuditRepository;

    public AdminController(LoginAuditRepository loginAuditRepository) {
        this.loginAuditRepository = loginAuditRepository;
    }

    @Operation(summary = "Admin access test", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Admin access granted"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    @GetMapping("/test")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminOnly(){
        return "ADMIN ACCESS GRANTED";
    }

    @Operation(summary = "Get login audit logs", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Audit logs fetched"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @GetMapping("/audit/logins")
    @PreAuthorize("hasRole('ADMIN')")
    public List<LoginAudit> getLoginAudits(){
        return loginAuditRepository.findAll();
    }
}