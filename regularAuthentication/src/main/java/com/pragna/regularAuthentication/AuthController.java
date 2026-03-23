package com.pragna.regularAuthentication;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;

    private static final String PROFILE_TOKEN_URL =
            "http://localhost:9093/api/profile/token";

    // WebClient preserves Set-Cookie headers from profile service so the
    // refreshToken cookie is correctly forwarded to the browser.
    private final WebClient webClient = WebClient.create();

    public AuthController(UserService userService,
                          AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    // ── POST /api/auth/register ───────────────────────────────────────
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody RegisterRequest req) {
        try {
            User user = new User();
            user.setUsername(req.getUsername());
            user.setPassword(req.getPassword());
            user.setEmail(req.getEmail());

            String role = (req.getRole() != null && !req.getRole().isBlank())
                    ? req.getRole() : "ROLE_USER";
            userService.registerUser(user, role);

            Map<String, String> res = new HashMap<>();
            res.put("message",  "User registered successfully");
            res.put("username", req.getUsername());
            res.put("role",     role);
            return ResponseEntity.status(HttpStatus.CREATED).body(res);

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("message", e.getMessage()));
        }
    }

    // ── POST /api/auth/login ──────────────────────────────────────────
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestBody LoginRequest req,
            HttpServletResponse httpResponse) {
        try {
            Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword())
            );

            boolean isAdmin = auth.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
            String role     = isAdmin ? "ROLE_ADMIN" : "ROLE_USER";
            String username = auth.getName();

            User userEntity = userService.findByUsername(username);
            String email = (userEntity != null && userEntity.getEmail() != null)
                    ? userEntity.getEmail() : "";

            Map<String, Object> profileResponse =
                    callProfileServiceAndForwardCookie(
                        username, username, email, "", role,
                        "local", "regular", httpResponse);

            profileResponse.put("message", "Login successful");
            return ResponseEntity.ok(profileResponse);

        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid username or password"));
        }
    }

    // ── POST /api/auth/logout ─────────────────────────────────────────
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletResponse httpResponse) {
        // Clear the refreshToken cookie
        httpResponse.addHeader("Set-Cookie",
                "refreshToken=; Path=/api/profile/refresh; HttpOnly; Max-Age=0; SameSite=Strict");
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    // ── POST /api/auth/oauth2/save-user ──────────────────────────────
    // Called internally by oauth2-service after successful provider login
    @PostMapping("/oauth2/save-user")
    public ResponseEntity<Map<String, Object>> saveOAuth2User(
            @RequestBody Map<String, String> req,
            HttpServletResponse httpResponse) {
        try {
            String username    = req.getOrDefault("username",    "");
            String email       = req.getOrDefault("email",       "");
            String displayName = req.getOrDefault("displayName", username);
            String avatar      = req.getOrDefault("avatar",      "");
            String provider    = req.getOrDefault("provider",    "oauth2");

            // Upsert user (creates if new, skips if exists)
            if (userService.findByUsername(username) == null) {
                User oauthUser = new User();
                oauthUser.setUsername(username);
                oauthUser.setPassword(java.util.UUID.randomUUID().toString());
                oauthUser.setEmail(email);
                oauthUser.setDisplayName(displayName);
                oauthUser.setAvatarUrl(avatar);
                oauthUser.setProvider(provider);
                userService.registerUser(oauthUser, "ROLE_USER");
            }

            Map<String, Object> profileResponse =
                    callProfileServiceAndForwardCookie(
                        username, displayName, email, avatar,
                        "ROLE_USER", provider, "oauth2", httpResponse);

            profileResponse.put("message", "OAuth2 login successful");
            return ResponseEntity.ok(profileResponse);

        } catch (Exception e) {
            System.err.println("[AUTH] OAuth2 save-user failed: " + e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("message", "OAuth2 registration failed"));
        }
    }

    // ── Helper: call profile service and forward its Set-Cookie ──────
    @SuppressWarnings("unchecked")
    private Map<String, Object> callProfileServiceAndForwardCookie(
            String username, String displayName, String email, String avatar,
            String role, String provider, String loginMethod,
            HttpServletResponse httpResponse) {

        Map<String, String> body = new HashMap<>();
        body.put("username",    username);
        body.put("displayName", displayName);
        body.put("email",       email);
        body.put("avatar",      avatar);
        body.put("role",        role);
        body.put("provider",    provider);
        body.put("loginMethod", loginMethod);

        try {
            Map<String, Object> result = webClient.post()
                    .uri(PROFILE_TOKEN_URL)
                    .bodyValue(body)
                    .exchangeToMono(clientResponse -> {
                        // Copy Set-Cookie from profile service → browser
                        List<String> cookies = clientResponse.headers()
                                .asHttpHeaders()
                                .getValuesAsList("Set-Cookie");
                        System.out.printf("[AUTH] Forwarding %d Set-Cookie header(s)%n",
                                cookies.size());
                        cookies.forEach(v -> httpResponse.addHeader("Set-Cookie", v));
                        return clientResponse.bodyToMono(Map.class);
                    })
                    .map(m -> new HashMap<String, Object>(m))
                    .block();

            return result != null ? result : new HashMap<>();

        } catch (Exception e) {
            System.err.println("[AUTH] Profile service unreachable: " + e.getMessage());
            return new HashMap<>(Map.of("message",
                    "Profile service unavailable — please retry"));
        }
    }
}
