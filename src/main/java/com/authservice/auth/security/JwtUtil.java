package com.authservice.auth.security;

import java.security.Key;
import java.util.Date;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

    private static final String SECRET =
            "THIS_IS_A_STRONG_PRODUCTION_SECRET_KEY_1234567890123456";

    private static final long ACCESS_EXPIRATION =
            1000 * 60*5; // 10 minute

    private static final long REFRESH_EXPIRATION =
            1000L * 60 * 60 * 24 * 7; // 7 days

    private final Key key = Keys.hmacShaKeyFor(SECRET.getBytes());

    // ACCESS TOKEN
    public String generateAccessToken(String email, String role) {
        return Jwts.builder()
                .setSubject(email)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_EXPIRATION))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // REFRESH TOKEN
    public String generateRefreshToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_EXPIRATION))
                .signWith(key, SignatureAlgorithm.HS256)
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
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    // SIMPLE VALIDATION
    public boolean validateToken(String token) {
        return !isTokenExpired(token);
    }

    // CHECK EXPIRATION
    private boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date());
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