package com.observatory.backend.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {

    private final SecretKey secretKey;

    // Token validity: 1 hour
    private static final long EXPIRATION_TIME =
            60 * 60 * 1000L;

    public JwtService(
            @Value("${APP_JWT_SECRET:dev-only-long-secret-key-change-this-before-deployment-123456789}")
            String secret) {

        this.secretKey =
                Keys.hmacShaKeyFor(
                        secret.getBytes(StandardCharsets.UTF_8)
                );
    }

    // =========================================================
    // GENERATE JWT
    // =========================================================

    public String generateToken(String email) {

        Date now = new Date();

        Date expiration =
                new Date(
                        now.getTime() + EXPIRATION_TIME
                );

        return Jwts.builder()
                .subject(email)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(secretKey)
                .compact();
    }

    // =========================================================
    // EXTRACT EMAIL
    // =========================================================

    public String extractEmail(String token) {

        return getClaims(token)
                .getSubject();
    }

    // =========================================================
    // VALIDATE TOKEN
    // =========================================================

    public boolean isTokenValid(String token) {

        try {

            getClaims(token);
            return true;

        } catch (Exception e) {

            return false;
        }
    }

    // =========================================================
    // PARSE CLAIMS
    // =========================================================

    private Claims getClaims(String token) {

        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}