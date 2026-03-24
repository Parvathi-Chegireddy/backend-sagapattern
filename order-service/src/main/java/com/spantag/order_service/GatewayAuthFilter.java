package com.spantag.order_service;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class GatewayAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String username = request.getHeader("X-Auth-Username");
        String role     = request.getHeader("X-Auth-Role");

        if (username != null && !username.isBlank()) {

            // ✅ FIX: The JWT stores the role as "ROLE_USER" (with the prefix already
            // included). SimpleGrantedAuthority must store the full string "ROLE_USER"
            // so that Spring's @PreAuthorize("hasAnyAuthority('ROLE_USER')") works.
            //
            // We normalise here defensively:
            //   • "ROLE_USER"  → stored as "ROLE_USER"  (no double-prefix)
            //   • "USER"       → stored as "ROLE_USER"  (prefix added)
            //   • null / blank → empty authority list
            List<SimpleGrantedAuthority> authorities;
            if (role != null && !role.isBlank()) {
                String normalised = role.startsWith("ROLE_") ? role : "ROLE_" + role;
                authorities = List.of(new SimpleGrantedAuthority(normalised));
            } else {
                authorities = List.of();
            }

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(username, null, authorities));
        }

        filterChain.doFilter(request, response);
    }
}
