package com.amaris.hkt.auth.api.service.impl;

import com.amaris.hkt.auth.api.entity.RefreshToken;
import com.amaris.hkt.auth.api.entity.User;
import com.amaris.hkt.auth.api.enums.Role;
import com.amaris.hkt.auth.api.exception.BusinessException;
import com.amaris.hkt.auth.api.repository.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenService Tests")
class RefreshTokenServiceImplTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private RefreshTokenServiceImpl refreshTokenService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .userId(1)
                .username("testuser")
                .email("test@example.com")
                .password("hashedpassword")
                .role(Role.USER)
                .build();

        // Mock the refreshExpiration property
        ReflectionTestUtils.setField(refreshTokenService, "refreshExpiration", 604800000L);
    }

    @Test
    @DisplayName("Should create refresh token successfully")
    void testCreateRefreshToken() {
        // Arrange
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> {
                    RefreshToken rt = invocation.getArgument(0);
                    rt.setRefreshTokenId(1);
                    return rt;
                });

        // Act
        RefreshToken result = refreshTokenService.createRefreshToken(testUser);

        // Assert
        assertNotNull(result);
        assertEquals(testUser, result.getUser());
        assertNotNull(result.getToken());
        assertNotNull(result.getExpiryDate());
        verify(refreshTokenRepository).revokeAllUserTokens(testUser);
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Should verify valid refresh token")
    void testVerifyRefreshToken_Valid() {
        // Arrange
        String token = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .refreshTokenId(1)
                .user(testUser)
                .token(token)
                .expiryDate(OffsetDateTime.now().plusDays(7))
                .revoked(false)
                .build();

        when(refreshTokenRepository.findByToken(token)).thenReturn(Optional.of(refreshToken));

        // Act
        RefreshToken result = refreshTokenService.verifyRefreshToken(token);

        // Assert
        assertNotNull(result);
        assertEquals(token, result.getToken());
        assertFalse(result.getRevoked());
        verify(refreshTokenRepository).findByToken(token);
    }

    @Test
    @DisplayName("Should throw exception for revoked refresh token")
    void testVerifyRefreshToken_Revoked() {
        // Arrange
        String token = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .refreshTokenId(1)
                .user(testUser)
                .token(token)
                .expiryDate(OffsetDateTime.now().plusDays(7))
                .revoked(true)
                .build();

        when(refreshTokenRepository.findByToken(token)).thenReturn(Optional.of(refreshToken));

        // Act & Assert
        assertThrows(BusinessException.class, () -> refreshTokenService.verifyRefreshToken(token));
        verify(refreshTokenRepository).findByToken(token);
    }

    @Test
    @DisplayName("Should throw exception for expired refresh token")
    void testVerifyRefreshToken_Expired() {
        // Arrange
        String token = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .refreshTokenId(1)
                .user(testUser)
                .token(token)
                .expiryDate(OffsetDateTime.now().minusHours(1))
                .revoked(false)
                .build();

        when(refreshTokenRepository.findByToken(token)).thenReturn(Optional.of(refreshToken));

        // Act & Assert
        assertThrows(BusinessException.class, () -> refreshTokenService.verifyRefreshToken(token));
    }

    @Test
    @DisplayName("Should throw exception for non-existent refresh token")
    void testVerifyRefreshToken_NotFound() {
        // Arrange
        String token = "nonexistent_token";
        when(refreshTokenRepository.findByToken(token)).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(BusinessException.class, () -> refreshTokenService.verifyRefreshToken(token));
    }

    @Test
    @DisplayName("Should revoke all user tokens")
    void testRevokeAllUserTokens() {
        // Arrange
        // Act
        refreshTokenService.revokeAllUserTokens(testUser);

        // Assert
        verify(refreshTokenRepository).revokeAllUserTokens(testUser);
    }

    @Test
    @DisplayName("Should revoke all tokens in system")
    void testRevokeAllTokens() {
        // Arrange
        when(refreshTokenRepository.revokeAllTokens()).thenReturn(5);

        // Act
        refreshTokenService.revokeAllTokens();

        // Assert
        verify(refreshTokenRepository).revokeAllTokens();
    }
}

