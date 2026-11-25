package ru.itmo.infosec;

import java.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
class ApiFilter extends OncePerRequestFilter {
    static final String OWNER_ID = "verifiedOwnerId";
    private final Authentication auth;

    ApiFilter(Authentication auth) {
        this.auth = auth;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");

        if (request.getServletPath().startsWith("/api/")) {
            var subject = auth.verifyToken(request.getHeader(HttpHeaders.AUTHORIZATION));
            if (subject.isEmpty()) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"error\":\"Valid bearer token required\"}");
                return;
            }
            request.setAttribute(OWNER_ID, subject.getAsLong());
        }
        chain.doFilter(request, response);
    }
}
