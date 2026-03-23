package com.spantag.Apigatewayapplication;


import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;

@Configuration
public class GatewayConfig {

    /**
     * FIX: The separate stripInternalHeadersFilter GlobalFilter has been REMOVED.
     *
     * Root cause of the 401 bug:
     * GlobalFilter beans (even with @Order(-2)) are adapted into GatewayFilterAdapters
     * and end up at the END of the per-route filter chain — AFTER route-level
     * GatewayFilters like JwtAuthFilter (order=1). So the strip was running AFTER
     * the inject, erasing the X-Auth-Username and X-Auth-Role headers before they
     * reached the downstream services. Downstream GatewayAuthFilter found no headers,
     * left the SecurityContext as anonymous, and Spring Security returned 401.
     *
     * The header stripping is now done at the TOP of JwtAuthFilter.apply(), which
     * is the correct place: strip client headers → validate JWT → inject trusted headers.
     * This guarantees the strip always happens before the inject within the same filter.
     */

    /**
     * Logging filter — request/response logging only. Kept as GlobalFilter
     * since logging order relative to route filters doesn't matter for correctness.
     */
    @Bean
    public GlobalFilter loggingFilter() {
        return (exchange, chain) -> {
            ServerHttpRequest req = exchange.getRequest();
            System.out.printf("[GATEWAY] %s %s  Auth: %s%n",
                    req.getMethod(),
                    req.getURI(),
                    req.getHeaders().getFirst(HttpHeaders.AUTHORIZATION) != null
                            ? "Bearer ***" : "none");
            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                ServerHttpResponse res = exchange.getResponse();
                System.out.printf("[GATEWAY] Response: %s%n", res.getStatusCode());
            }));
        };
    }
}