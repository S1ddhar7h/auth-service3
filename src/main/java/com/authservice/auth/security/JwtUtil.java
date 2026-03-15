package com.authservice.auth.security;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

import jakarta.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access.expiration}")
    private long accessExpiration;

    @Value("${jwt.refresh.expiration}")
    private long refreshExpiration;

    private Key key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    // ACCESS TOKEN
    public String generateAccessToken(String email, String role) {

        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(email)
                .claim("role", role)
                .claim("type", "ACCESS")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessExpiration))
                .signWith(key)
                .compact();
    }

    // REFRESH TOKEN
    public String generateRefreshToken(String email) {

        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(email)
                .claim("type", "REFRESH")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpiration))
                .signWith(key)
                .compact();
    }

    // EXTRACT USERNAME
    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    // EXTRACT ROLE
    public String extractRole(String token) {
        return extractClaims(token).get("role", String.class);
    }

    // TOKEN VALIDATION WITH USERDETAILS
    public boolean validateToken(String token, UserDetails userDetails) {

        try {

            final String username = extractUsername(token);

            return username.equals(userDetails.getUsername())
                    && !isTokenExpired(token);

        } catch (JwtException | IllegalArgumentException e) {

            return false;
        }
    }

    // SIMPLE VALIDATION
    public boolean validateToken(String token) {

        try {

            return !isTokenExpired(token);

        } catch (JwtException | IllegalArgumentException e) {

            return false;
        }
    }

    // CHECK EXPIRATION
    private boolean isTokenExpired(String token) {

        return extractClaims(token)
                .getExpiration()
                .before(new Date());
    }

    // EXTRACT EXPIRATION DATE (NEW)
    public Date extractExpiration(String token) {
        return extractClaims(token).getExpiration();
    }

    // GET REMAINING TOKEN EXPIRATION (NEW)
    public long getRemainingExpiration(String token) {

        Date expiration = extractExpiration(token);

        long remainingTime = expiration.getTime() - System.currentTimeMillis();

        return remainingTime / 1000;
    }

    // EXTRACT ALL CLAIMS
    private Claims extractClaims(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}