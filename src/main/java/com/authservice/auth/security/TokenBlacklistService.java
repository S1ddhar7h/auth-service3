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
    public void blacklist(String token) {

        redisTemplate.opsForValue()
                .set("blacklist:" + token, "true", Duration.ofMinutes(10));
    }

    // check token
    public boolean isBlacklisted(String token) {

        return redisTemplate.hasKey("blacklist:" + token);
    }
}