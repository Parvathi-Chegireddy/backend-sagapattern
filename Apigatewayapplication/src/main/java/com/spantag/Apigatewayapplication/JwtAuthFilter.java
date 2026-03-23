package com.spantag.Apigatewayapplication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class JwtAuthFilter extends
        AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    private final SecretKey key;

    public JwtAuthFilter(@Value("${jwt.secret}") String secret) {
        super(Config.class);
        this.key = Keys.hmacShaKeyFor(
                secret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // ── STEP 1: Strip any X-Auth-* headers the CLIENT might have injected ──
            // This MUST happen here, inside the route-level GatewayFilter, because
            // GlobalFilters (from GatewayConfig) run AFTER route filters in the
            // adapted filter chain — meaning a separate GlobalFilter strip would
            // execute AFTER we already injected the validated headers, wiping them.
            //
            // By stripping here first, we guarantee:
            //   client X-Auth-Username: hacker  →  removed  →  replaced with JWT claim
            ServerHttpRequest stripped = exchange.getRequest().mutate()
                    .headers(h -> {
                        h.remove("X-Auth-Username");
                        h.remove("X-Auth-Role");
                        h.remove("X-Auth-Email");
                        h.remove("X-Auth-Provider");
                    })
                    .build();
            exchange = exchange.mutate().request(stripped).build();

            ServerHttpRequest request = exchange.getRequest();

            // ── STEP 2: Extract Bearer token (header first, cookie fallback) ──
            String token = extractFromHeader(request);
            if (token == null) token = extractFromCookie(request, "accessToken");

            if (token == null) {
                return reject(exchange.getResponse(),
                        HttpStatus.UNAUTHORIZED,
                        "Missing Authorization header or accessToken cookie");
            }

            // ── STEP 3: Validate JWT and inject trusted X-Auth-* headers ──
            try {
                Claims claims = Jwts.parser()
                        .verifyWith(key)
                        .build()
                        .parseSignedClaims(token)
                        .getPayload();

                // Must be an access token, not a refresh token
                String type = claims.get("type", String.class);
                if (!"access".equals(type)) {
                    return reject(exchange.getResponse(),
                            HttpStatus.UNAUTHORIZED, "Invalid token type");
                }

                String username = claims.getSubject();
                String role     = claims.get("role",     String.class);
                String email    = claims.get("email",    String.class);
                String provider = claims.get("provider", String.class);

                // Inject validated claims. Downstream GatewayAuthFilter reads
                // these to build Spring Security's SecurityContext.
                ServerHttpRequest mutated = request.mutate()
                        .header("X-Auth-Username", username != null ? username : "")
                        .header("X-Auth-Role",     role     != null ? role     : "")
                        .header("X-Auth-Email",    email    != null ? email    : "")
                        .header("X-Auth-Provider", provider != null ? provider : "")
                        .build();

                return chain.filter(
                        exchange.mutate().request(mutated).build());

            } catch (JwtException | IllegalArgumentException e) {
                return reject(exchange.getResponse(),
                        HttpStatus.UNAUTHORIZED,
                        "Invalid or expired token");
            }
        };
    }

    private String extractFromHeader(ServerHttpRequest request) {
        String h = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        return (h != null && h.startsWith("Bearer ")) ? h.substring(7) : null;
    }

    private String extractFromCookie(ServerHttpRequest request, String name) {
        HttpCookie cookie = request.getCookies().getFirst(name);
        return cookie != null ? cookie.getValue() : null;
    }

    private Mono<Void> reject(ServerHttpResponse response,
                              HttpStatus status, String message) {
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] bytes = ("{\"message\":\"" + message + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }

    public static class Config {}
}