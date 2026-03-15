package com.authservice.auth.security;

import java.time.Duration;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class TokenBlacklistService {

    private final StringRedisTemplate redisTemplate;

    public TokenBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // blacklist token
    public void blacklist(String token, long expirySeconds) {

        redisTemplate.opsForValue()
                .set("blacklist:" + token, "true", Duration.ofSeconds(expirySeconds));
    
    }

   // check token
    public boolean isBlacklisted(String token) {

        return redisTemplate.hasKey("blacklist:" + token);
    }
}