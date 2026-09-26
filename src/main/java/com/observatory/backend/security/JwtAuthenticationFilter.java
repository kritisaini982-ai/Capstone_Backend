package com.observatory.backend.security;

import com.observatory.backend.service.JwtService;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter implements Filter {

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public void doFilter(
            ServletRequest request,
            ServletResponse response,
            FilterChain filterChain
    ) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String path = httpRequest.getRequestURI();

// Public authentication endpoints
if (path.equals("/api/v1/auth/login")
        || path.equals("/api/v1/auth/register")) {

    filterChain.doFilter(request, response);
    return;
}

        // Allow browser CORS preflight requests
        if ("OPTIONS".equalsIgnoreCase(httpRequest.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String authorizationHeader =
                httpRequest.getHeader("Authorization");

        // Authorization header missing
        if (authorizationHeader == null
                || !authorizationHeader.startsWith("Bearer ")) {

            httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write(
                    "{\"status\":\"ERROR\",\"message\":\"Authentication token is required\"}"
            );
            return;
        }

        String token = authorizationHeader.substring(7).trim();

        // JWT validation
        if (token.isEmpty() || !jwtService.isTokenValid(token)) {

            httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write(
                    "{\"status\":\"ERROR\",\"message\":\"Invalid or expired authentication token\"}"
            );
            return;
        }

        try {
            String email = jwtService.extractEmail(token);

            // Store authenticated user's email for controllers
            httpRequest.setAttribute("authenticatedEmail", email);

            filterChain.doFilter(request, response);

        } catch (Exception e) {

            httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write(
                    "{\"status\":\"ERROR\",\"message\":\"Invalid authentication token\"}"
            );
        }
    }
}
