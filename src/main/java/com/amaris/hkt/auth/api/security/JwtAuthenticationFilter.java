package com.amaris.hkt.auth.api.security;

import com.amaris.hkt.auth.api.entity.User;
import com.amaris.hkt.auth.api.repository.UserRepository;
import com.amaris.hkt.auth.api.service.RevokedTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService           jwtService;
    private final UserRepository       userRepository;
    private final RevokedTokenService  revokedTokenService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt      = authHeader.substring(7);
        final String username;

        try {
            username = jwtService.extractUsername(jwt);
        } catch (Exception e) {
            log.warn("JWT inválido: {}", e.getMessage());
            filterChain.doFilter(request, response);
            return;
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            User user = userRepository.findByUsername(username).orElse(null);

            if (user != null && jwtService.isTokenValid(jwt, user)) {
                // Validar que el token no esté revocado
                if (revokedTokenService.isTokenRevoked(jwt)) {
                    log.warn("⛔ Token revocado: {}", username);
                    filterChain.doFilter(request, response);
                    return;
                }
                
                var authorities = user.getAuthorities();
                log.info("JWT VÁLIDO - Username: {}, Rol: {}, Autoridades: {}",
                         username, user.getRole(), authorities);

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(user, null, authorities);
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);

                log.info("Authentication establecida en SecurityContext");
            } else {
                log.warn("✗ JWT inválido o usuario no encontrado: {}", username);
            }
        }

        filterChain.doFilter(request, response);
    }
}
