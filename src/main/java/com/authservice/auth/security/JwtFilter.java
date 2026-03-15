package com.authservice.auth.security;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.authservice.auth.service.CustomUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private static final Logger log =
            LoggerFactory.getLogger(JwtFilter.class);

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;

    public JwtFilter(JwtUtil jwtUtil,
                     CustomUserDetailsService userDetailsService,
                     TokenBlacklistService tokenBlacklistService) {

        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    // Skip only public endpoints
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        String path = request.getServletPath();

        return path.equals("/auth/login")
                || path.equals("/auth/signup")
                || path.equals("/auth/refresh") 
                || path.equals("/auth/forgot-password")
                || path.equals("/auth/reset-password")
                || path.equals("/auth/verify");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
    	
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.debug("No JWT token found for {}", request.getRequestURI());
            filterChain.doFilter(request, response);
            return;
            
        }

        String token = authHeader.substring(7);

        // blacklist check
        if (tokenBlacklistService.isBlacklisted(token)) {
            log.warn("Blacklisted token used: {}", request.getRequestURI());
            	
            filterChain.doFilter(request, response);
            return; 
            
        }

        String username;

        try {
            username = jwtUtil.extractUsername(token);
        } catch (Exception e) {
            log.error("Invalid JWT token: {}", e.getMessage());
            filterChain.doFilter(request, response);
            return;
        }

        if (username != null &&
                SecurityContextHolder.getContext().getAuthentication() == null) {
        	

            UserDetails userDetails = 
            		
                    userDetailsService.loadUserByUsername(username);

            if (jwtUtil.validateToken(token, userDetails)) {

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());

                authToken.setDetails(
                        new WebAuthenticationDetailsSource()
                                .buildDetails(request));

                SecurityContextHolder.getContext()
                        .setAuthentication(authToken);

                log.debug("JWT authentication success for {}", username);
            }
        }

        filterChain.doFilter(request, response);
    }
}