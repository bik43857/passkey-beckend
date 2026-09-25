package com.example.auth.security;

import com.example.auth.config.AppProperties;
import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Section 10 "rate limiting" / "login attempt protection", the network-level
 * half (the per-account lockout in PasswordAuthenticationService is the
 * other half). Buckets are per-(category, client IP) and held in memory —
 * fine for a single instance; behind a load balancer with multiple backend
 * instances, swap this for Bucket4j's Redis/Hazelcast-backed distributed
 * ProxyManager instead so limits are shared across instances (see Bucket4j
 * docs — the Bucket interface itself doesn't change, only how it's built).
 */
@Component
public class RateLimiterService {

    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final AppProperties.RateLimit config;

    public RateLimiterService(AppProperties appProperties) {
        this.config = appProperties.rateLimit();
    }

    public boolean tryConsume(String category, String clientIp) {
        String key = category + ":" + clientIp;
        Bucket bucket = buckets.computeIfAbsent(key, k -> newBucket(category));
        return bucket.tryConsume(1);
    }

    private Bucket newBucket(String category) {
        int perMinute = switch (category) {
            case "register" -> config.registerAttemptsPerMinute();
            case "login" -> config.loginAttemptsPerMinute();
            default -> 10;
        };
        return Bucket.builder()
                .addLimit(limit -> limit.capacity(perMinute).refillGreedy(perMinute, Duration.ofMinutes(1)))
                .build();
    }
}
