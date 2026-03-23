package com.pragna.profile;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private final JwtService jwtService;

    public ProfileController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    // ── POST /api/profile/token ───────────────────────────────────────
    // Called internally by auth-service and oauth2-service after login.
    // Issues access token (in body) + refresh token (HttpOnly cookie).
    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> issueToken(
            @RequestBody ProfileRequest req,
            HttpServletResponse response) {

        System.out.printf("[PROFILE] Issuing tokens → username=%s provider=%s method=%s%n",
                req.getUsername(), req.getProvider(), req.getLoginMethod());

        String username    = nvl(req.getUsername(),    "unknown");
        String role        = nvl(req.getRole(),        "ROLE_USER");
        String provider    = nvl(req.getProvider(),    "local");
        String loginMethod = nvl(req.getLoginMethod(), "regular");
        String email       = nvl(req.getEmail(),       "");
        String displayName = nvl(req.getDisplayName(), req.getUsername());
        String avatar      = nvl(req.getAvatar(),      "");

        String accessToken  = jwtService.issueAccessToken(
                username, role, provider, loginMethod, email, displayName, avatar);
        String refreshToken = jwtService.issueRefreshToken(username);

        // Single Set-Cookie header via addHeader — do NOT call addCookie() as well.
        // Two Set-Cookie headers cause browser to store a corrupted date string.
        setRefreshTokenCookie(response, refreshToken);

        Map<String, Object> body = new HashMap<>();
        body.put("accessToken",  accessToken);
        body.put("username",     username);
        body.put("displayName",  displayName);
        body.put("email",        email);
        body.put("avatar",       avatar);
        body.put("role",         role);
        body.put("provider",     provider);
        body.put("loginMethod",  loginMethod);
        body.put("roleLabel",    buildRoleLabel(req));
        body.put("methodLabel",  buildMethodLabel(req));
        body.put("expiresIn",    900);
        return ResponseEntity.ok(body);
    }

    // ── POST /api/profile/refresh ─────────────────────────────────────
    // Called by the frontend on page load and every 14 min.
    // Validates the refreshToken cookie, issues a new access+refresh pair.
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(
            HttpServletRequest request,
            HttpServletResponse response) {

        String refreshToken = extractRefreshCookie(request);

        if (refreshToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "No refresh token"));
        }

        if (!jwtService.isValid(refreshToken) || !jwtService.isRefreshToken(refreshToken)) {
            clearRefreshTokenCookie(response);
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Refresh token invalid or expired"));
        }

        String username = jwtService.validateAndGetClaims(refreshToken).getSubject();

        // Carry over claims from the (possibly expired) access token
        String role        = "ROLE_USER";
        String email       = "";
        String displayName = username;
        String avatar      = "";
        String provider    = "local";
        String loginMethod = "regular";

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                var claims = jwtService.getClaimsIgnoringExpiry(authHeader.substring(7));
                if (claims != null && username.equals(claims.getSubject())) {
                    role        = nvl(claims.get("role",        String.class), role);
                    email       = nvl(claims.get("email",       String.class), email);
                    displayName = nvl(claims.get("displayName", String.class), displayName);
                    avatar      = nvl(claims.get("avatar",      String.class), avatar);
                    provider    = nvl(claims.get("provider",    String.class), provider);
                    loginMethod = nvl(claims.get("loginMethod", String.class), loginMethod);
                }
            } catch (Exception ignored) {}
        }

        String newAccessToken  = jwtService.issueAccessToken(
                username, role, provider, loginMethod, email, displayName, avatar);
        String newRefreshToken = jwtService.issueRefreshToken(username);
        setRefreshTokenCookie(response, newRefreshToken);

        Map<String, Object> body = new HashMap<>();
        body.put("accessToken",  newAccessToken);
        body.put("username",     username);
        body.put("displayName",  displayName);
        body.put("email",        email);
        body.put("role",         role);
        body.put("roleLabel",    "ROLE_ADMIN".equals(role) ? "ADMIN" : "USER");
        body.put("methodLabel",  "oauth2".equals(loginMethod) ? cap(provider) + " OAuth2" : "Password Login");
        body.put("provider",     provider);
        body.put("loginMethod",  loginMethod);
        body.put("expiresIn",    900);
        return ResponseEntity.ok(body);
    }

    // ── POST /api/profile/logout ──────────────────────────────────────
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletResponse response) {
        clearRefreshTokenCookie(response);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    // ── GET /api/profile/validate ─────────────────────────────────────
    // Used by gateway or other services to validate an access token
    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validate(
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Missing Authorization header"));
        }
        String token = authHeader.substring(7);
        if (!jwtService.isValid(token) || !jwtService.isAccessToken(token)) {
            return ResponseEntity.status(401).body(Map.of("error", "Token invalid or expired"));
        }
        var claims = jwtService.validateAndGetClaims(token);
        Map<String, Object> body = new HashMap<>();
        body.put("valid",       true);
        body.put("username",    claims.getSubject());
        body.put("role",        claims.get("role"));
        body.put("provider",    claims.get("provider"));
        body.put("loginMethod", claims.get("loginMethod"));
        body.put("email",       claims.get("email"));
        body.put("displayName", claims.get("displayName"));
        body.put("avatar",      claims.get("avatar"));
        return ResponseEntity.ok(body);
    }

    /* ── Cookie helpers ─────────────────────────────────────────────── */

    private void setRefreshTokenCookie(HttpServletResponse response, String token) {
        long maxAgeSeconds = jwtService.getRefreshTokenExpiryMs() / 1000;
        response.addHeader("Set-Cookie",
                "refreshToken=" + token
                + "; Path=/api/profile/refresh"
                + "; HttpOnly"
                + "; Max-Age=" + maxAgeSeconds
                + "; SameSite=Strict");
    }

    private void clearRefreshTokenCookie(HttpServletResponse response) {
        response.addHeader("Set-Cookie",
                "refreshToken=; Path=/api/profile/refresh; HttpOnly; Max-Age=0; SameSite=Strict");
    }

    private String extractRefreshCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> "refreshToken".equals(c.getName()))
                .map(jakarta.servlet.http.Cookie::getValue)
                // Only accept JWTs — filter out corrupted date strings
                .filter(v -> v != null && v.startsWith("eyJ"))
                .findFirst()
                .orElse(null);
    }

    /* ── Label helpers ──────────────────────────────────────────────── */

    private String buildRoleLabel(ProfileRequest req) {
        if ("ROLE_ADMIN".equals(req.getRole())) return "ADMIN";
        if ("oauth2".equals(req.getLoginMethod()) && req.getProvider() != null)
            return req.getProvider().toUpperCase() + " USER";
        return "USER";
    }

    private String buildMethodLabel(ProfileRequest req) {
        if ("oauth2".equals(req.getLoginMethod()) && req.getProvider() != null) {
            String p = req.getProvider();
            return Character.toUpperCase(p.charAt(0)) + p.substring(1) + " OAuth2";
        }
        return "Password Login";
    }

    private String nvl(String v, String fallback) {
        return (v != null && !v.isBlank()) ? v : fallback;
    }

    private String cap(String s) {
        if (s == null || s.isEmpty()) return s;
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }
}
