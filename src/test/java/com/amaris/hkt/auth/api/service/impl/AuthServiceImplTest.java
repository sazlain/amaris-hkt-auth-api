package com.amaris.hkt.auth.api.service.impl;

import com.amaris.hkt.auth.api.dto.request.LoginRequest;
import com.amaris.hkt.auth.api.dto.request.RegisterRequest;
import com.amaris.hkt.auth.api.dto.response.AuthResponse;
import com.amaris.hkt.auth.api.dto.response.ValidateTokenResponse;
import com.amaris.hkt.auth.api.entity.RefreshToken;
import com.amaris.hkt.auth.api.entity.User;
import com.amaris.hkt.auth.api.enums.Role;
import com.amaris.hkt.auth.api.exception.BusinessException;
import com.amaris.hkt.auth.api.repository.UserRepository;
import com.amaris.hkt.auth.api.security.JwtService;
import com.amaris.hkt.auth.api.service.RefreshTokenService;
import com.amaris.hkt.auth.api.service.RevokedTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.OffsetDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService Tests")
class AuthServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private RevokedTokenService revokedTokenService;

    @Mock
    private AuthenticationManager authenticationManager;

    @InjectMocks
    private AuthServiceImpl authService;

    private User testUser;
    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .userId(1)
                .username("testuser")
                .email("test@example.com")
                .password("hashedpassword")
                .role(Role.USER)
                .enabled(true)
                .build();

        registerRequest = new RegisterRequest();
        registerRequest.setUsername("newuser");
        registerRequest.setEmail("newuser@example.com");
        registerRequest.setPassword("Password123!");
        registerRequest.setRole(Role.USER);

        loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("Password123!");

        // Inyectar jwtExpiration (24 horas en milisegundos)
        ReflectionTestUtils.setField(authService, "jwtExpiration", 86400000L);
    }

    @Test
    @DisplayName("Should register user successfully")
    void testRegister_Success() {
        // Arrange
        when(userRepository.existsByUsername(registerRequest.getUsername())).thenReturn(false);
        when(userRepository.existsByEmail(registerRequest.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(registerRequest.getPassword())).thenReturn("hashedPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(jwtService.generateToken(any(User.class))).thenReturn("jwt_token");

        RefreshToken refreshToken = RefreshToken.builder()
                .user(testUser)
                .token("refresh_token")
                .expiryDate(OffsetDateTime.now().plusDays(7))
                .build();
        when(refreshTokenService.createRefreshToken(any(User.class))).thenReturn(refreshToken);

        // Act
        AuthResponse response = authService.register(registerRequest);

        // Assert
        assertNotNull(response);
        assertEquals("jwt_token", response.getAccessToken());
        assertEquals("refresh_token", response.getRefreshToken());
        verify(userRepository).existsByUsername(registerRequest.getUsername());
        verify(userRepository).existsByEmail(registerRequest.getEmail());
        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("Should throw exception when username already exists")
    void testRegister_UsernameExists() {
        // Arrange
        when(userRepository.existsByUsername(registerRequest.getUsername())).thenReturn(true);

        // Act & Assert
        assertThrows(BusinessException.class, () -> authService.register(registerRequest));
        verify(userRepository).existsByUsername(registerRequest.getUsername());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should throw exception when email already exists")
    void testRegister_EmailExists() {
        // Arrange
        when(userRepository.existsByUsername(registerRequest.getUsername())).thenReturn(false);
        when(userRepository.existsByEmail(registerRequest.getEmail())).thenReturn(true);

        // Act & Assert
        assertThrows(BusinessException.class, () -> authService.register(registerRequest));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should login user successfully")
    void testLogin_Success() {
        // Arrange
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.of(testUser));
        when(jwtService.generateToken(testUser)).thenReturn("jwt_token");

        RefreshToken refreshToken = RefreshToken.builder()
                .user(testUser)
                .token("refresh_token")
                .build();
        when(refreshTokenService.createRefreshToken(testUser)).thenReturn(refreshToken);

        // Act
        AuthResponse response = authService.login(loginRequest);

        // Assert
        assertNotNull(response);
        assertEquals("jwt_token", response.getAccessToken());
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(userRepository).findByUsername(loginRequest.getUsername());
    }

    @Test
    @DisplayName("Should throw exception when user not found during login")
    void testLogin_UserNotFound() {
        // Arrange
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(BusinessException.class, () -> authService.login(loginRequest));
    }

    @Test
    @DisplayName("Should logout user successfully")
    void testLogout_Success() {
        // Arrange
        String jwtToken = "jwt_token";
        when(userRepository.findByUsername(testUser.getUsername())).thenReturn(Optional.of(testUser));

        // Act
        authService.logout(testUser.getUsername(), jwtToken);

        // Assert
        verify(revokedTokenService).revokeToken(testUser, jwtToken, 86400000L);
        verify(revokedTokenService).cleanExpiredTokens();
        verify(refreshTokenService).revokeAllUserTokens(testUser);
    }

    @Test
    @DisplayName("Should throw exception when user not found during logout")
    void testLogout_UserNotFound() {
        // Arrange
        String jwtToken = "jwt_token";
        when(userRepository.findByUsername(testUser.getUsername())).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(BusinessException.class, () -> authService.logout(testUser.getUsername(), jwtToken));
    }

    @Test
    @DisplayName("Should validate token successfully")
    void testValidateToken_Valid() {
        // Arrange
        String token = "valid_jwt_token";
        when(jwtService.extractUsername(token)).thenReturn(testUser.getUsername());
        when(userRepository.findByUsername(testUser.getUsername())).thenReturn(Optional.of(testUser));
        when(jwtService.isTokenValid(token, testUser)).thenReturn(true);
        when(revokedTokenService.isTokenRevoked(token)).thenReturn(false);
        when(jwtService.extractExpiration(token)).thenReturn(new java.util.Date(System.currentTimeMillis() + 86400000L));

        // Act
        ValidateTokenResponse response = authService.validateToken(token);

        // Assert
        assertTrue(response.isValid());
        assertEquals("Token válido", response.getMessage());
        assertEquals(testUser.getUsername(), response.getUsername());
    }

    @Test
    @DisplayName("Should return invalid for revoked token")
    void testValidateToken_Revoked() {
        // Arrange
        String token = "revoked_jwt_token";
        when(jwtService.extractUsername(token)).thenReturn(testUser.getUsername());
        when(userRepository.findByUsername(testUser.getUsername())).thenReturn(Optional.of(testUser));
        when(jwtService.isTokenValid(token, testUser)).thenReturn(true);
        when(revokedTokenService.isTokenRevoked(token)).thenReturn(true);

        // Act
        ValidateTokenResponse response = authService.validateToken(token);

        // Assert
        assertFalse(response.isValid());
        assertEquals("Token revocado", response.getMessage());
    }

    @Test
    @DisplayName("Should return invalid for expired token")
    void testValidateToken_Expired() {
        // Arrange
        String token = "expired_jwt_token";
        when(jwtService.extractUsername(token)).thenReturn(testUser.getUsername());
        when(userRepository.findByUsername(testUser.getUsername())).thenReturn(Optional.of(testUser));
        when(jwtService.isTokenValid(token, testUser)).thenReturn(false);

        // Act
        ValidateTokenResponse response = authService.validateToken(token);

        // Assert
        assertFalse(response.isValid());
        assertEquals("Token inválido o expirado", response.getMessage());
    }

    @Test
    @DisplayName("Should return invalid for null token")
    void testValidateToken_NullToken() {
        // Act
        ValidateTokenResponse response = authService.validateToken(null);

        // Assert
        assertFalse(response.isValid());
        assertEquals("Token requerido", response.getMessage());
    }
}




