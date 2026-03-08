package com.authservice.auth.service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Refill;

@Service
public class RateLimiterService {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public boolean tryConsume(String key) {

        Bucket bucket = buckets.computeIfAbsent(key, k -> {

            Bandwidth limit = Bandwidth.classic(
                    5,
                    Refill.intervally(5, Duration.ofMinutes(1))
            );

            return Bucket.builder()
                    .addLimit(limit)
                    .build();
        });

        return bucket.tryConsume(1);
    }
}