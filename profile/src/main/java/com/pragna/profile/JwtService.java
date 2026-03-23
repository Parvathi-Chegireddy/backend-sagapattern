package com.pragna.profile;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {

    private final SecretKey key;
    private final long accessTokenExpiryMs;
    private final long refreshTokenExpiryMs;

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiry-ms}") long accessTokenExpiryMs,
            @Value("${jwt.refresh-token-expiry-ms}") long refreshTokenExpiryMs) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpiryMs  = accessTokenExpiryMs;
        this.refreshTokenExpiryMs = refreshTokenExpiryMs;
    }

    /** Issue a short-lived ACCESS token (15 min) — contains full profile claims */
    public String issueAccessToken(String username, String role,
                                   String provider, String loginMethod,
                                   String email, String displayName, String avatar) {
        return Jwts.builder()
                .subject(username)
                .claim("type",        "access")
                .claim("role",        role)
                .claim("provider",    provider)
                .claim("loginMethod", loginMethod)
                .claim("email",       email)
                .claim("displayName", displayName)
                .claim("avatar",      avatar)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpiryMs))
                .signWith(key)
                .compact();
    }

    /** Issue a long-lived REFRESH token (7 days) — minimal claims, delivered as HttpOnly cookie */
    public String issueRefreshToken(String username) {
        return Jwts.builder()
                .subject(username)
                .claim("type", "refresh")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshTokenExpiryMs))
                .signWith(key)
                .compact();
    }

    /** Validate token and return claims — throws JwtException if invalid/expired */
    public Claims validateAndGetClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Parse claims WITHOUT enforcing expiry.
     * Used by /refresh to read role/email from an expiring access token.
     * The refresh token cookie is what proves session validity — not the access token expiry.
     * Returns null if the token is structurally invalid (wrong signature, malformed).
     */
    public Claims getClaimsIgnoringExpiry(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .clockSkewSeconds(Integer.MAX_VALUE) // accept any expiry
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            return null;
        }
    }

    public boolean isValid(String token) {
        try { validateAndGetClaims(token); return true; }
        catch (JwtException | IllegalArgumentException e) { return false; }
    }

    public boolean isAccessToken(String token) {
        try {
            return "access".equals(validateAndGetClaims(token).get("type", String.class));
        } catch (Exception e) { return false; }
    }

    public boolean isRefreshToken(String token) {
        try {
            return "refresh".equals(validateAndGetClaims(token).get("type", String.class));
        } catch (Exception e) { return false; }
    }

    public long getRefreshTokenExpiryMs() { return refreshTokenExpiryMs; }
}