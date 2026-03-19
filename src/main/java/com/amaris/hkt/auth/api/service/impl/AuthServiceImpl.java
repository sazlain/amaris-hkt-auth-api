package com.amaris.hkt.auth.api.service.impl;

import com.amaris.hkt.auth.api.dto.request.LoginRequest;
import com.amaris.hkt.auth.api.dto.request.RefreshTokenRequest;
import com.amaris.hkt.auth.api.dto.request.RegisterRequest;
import com.amaris.hkt.auth.api.dto.response.AuthResponse;
import com.amaris.hkt.auth.api.dto.response.ValidateTokenResponse;
import com.amaris.hkt.auth.api.entity.RefreshToken;
import com.amaris.hkt.auth.api.entity.User;
import com.amaris.hkt.auth.api.enums.Role;
import com.amaris.hkt.auth.api.exception.BusinessException;
import com.amaris.hkt.auth.api.repository.UserRepository;
import com.amaris.hkt.auth.api.security.JwtService;
import com.amaris.hkt.auth.api.service.AuthService;
import com.amaris.hkt.auth.api.service.RefreshTokenService;
import com.amaris.hkt.auth.api.service.RevokedTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository        userRepository;
    private final PasswordEncoder       passwordEncoder;
    private final JwtService            jwtService;
    private final RefreshTokenService   refreshTokenService;
    private final RevokedTokenService   revokedTokenService;
    private final AuthenticationManager authenticationManager;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // Validar unicidad de username
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new BusinessException("El username '" + request.getUsername() + "' ya está en uso");
        }
        // Validar unicidad de email
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BusinessException("El email '" + request.getEmail() + "' ya está registrado");
        }

        // Crear el User
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole() != null ? request.getRole() : Role.USER)
                .build();

        userRepository.save(user);

        return buildAuthResponse(user);
    }

    @Override
    @Transactional
    public AuthResponse login(LoginRequest request) {
        // Spring Security lanza BadCredentialsException / DisabledException automáticamente
        // — GlobalExceptionHandler los convierte en 401
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new BusinessException("Usuario no encontrado"));

        return buildAuthResponse(user);
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(request.getRefreshToken());
        User user = refreshToken.getUser();
        return buildAuthResponse(user);
    }

    @Override
    @Transactional
    public void logout(String username, String jwtToken) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BusinessException("Usuario no encontrado"));
        
        // Revocar el JWT access token agregándolo a la blacklist
        revokedTokenService.revokeToken(user, jwtToken, jwtExpiration);
        
        // Limpiar tokens revocados expirados
        revokedTokenService.cleanExpiredTokens();
        
        // Revocar todos los refresh tokens del usuario
        refreshTokenService.revokeAllUserTokens(user);
    }

    @Override
    @Transactional
    public AuthResponse createUserWithRole(RegisterRequest request, Role role) {
        // Validar unicidad de username
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new BusinessException("El username '" + request.getUsername() + "' ya está en uso");
        }
        // Validar unicidad de email
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BusinessException("El email '" + request.getEmail() + "' ya está registrado");
        }

        // Crear el User con el rol especificado
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .build();

        userRepository.save(user);

        return buildAuthResponse(user);
    }

    // ── Helper ────────────────────────────────────────────────────────────

    private AuthResponse buildAuthResponse(User user) {
        String accessToken   = jwtService.generateToken(user);
        RefreshToken refresh = refreshTokenService.createRefreshToken(user);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refresh.getToken())
                .expiresIn(jwtExpiration)
                .user(AuthResponse.UserInfoResponse.builder()
                        .userId(user.getUserId())
                        .username(user.getUsername())
                        .email(user.getEmail())
                        .role(user.getRole())
                        .build())
                .build();
    }

    @Override
    public ValidateTokenResponse validateToken(String token) {
        try {
            // Validar que el token no sea nulo o vacío
            if (token == null || token.isBlank()) {
                return ValidateTokenResponse.builder()
                        .valid(false)
                        .message("Token requerido")
                        .validatedAt(java.time.OffsetDateTime.now())
                        .build();
            }

            // Extraer el username del token
            String username = jwtService.extractUsername(token);

            // Buscar el usuario
            User user = userRepository.findByUsername(username)
                    .orElse(null);

            if (user == null) {
                return ValidateTokenResponse.builder()
                        .valid(false)
                        .message("Usuario no encontrado")
                        .validatedAt(java.time.OffsetDateTime.now())
                        .build();
            }

            // Validar que el token sea válido (firma y no expirado)
            if (!jwtService.isTokenValid(token, user)) {
                return ValidateTokenResponse.builder()
                        .valid(false)
                        .message("Token inválido o expirado")
                        .validatedAt(java.time.OffsetDateTime.now())
                        .build();
            }

            // Validar que el token no esté revocado
            if (revokedTokenService.isTokenRevoked(token)) {
                return ValidateTokenResponse.builder()
                        .valid(false)
                        .message("Token revocado")
                        .validatedAt(java.time.OffsetDateTime.now())
                        .build();
            }

            // Token válido - retornar información del usuario
            return ValidateTokenResponse.builder()
                    .valid(true)
                    .message("Token válido")
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .role(user.getRole())
                    .expiresAt(jwtService.extractExpiration(token))
                    .validatedAt(java.time.OffsetDateTime.now())
                    .build();

        } catch (Exception e) {
            return ValidateTokenResponse.builder()
                    .valid(false)
                    .message("Error al validar token: " + e.getMessage())
                    .validatedAt(java.time.OffsetDateTime.now())
                    .build();
        }
    }
}


