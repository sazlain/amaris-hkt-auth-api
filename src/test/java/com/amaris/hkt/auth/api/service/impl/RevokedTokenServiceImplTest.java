package com.amaris.hkt.auth.api.service.impl;

import com.amaris.hkt.auth.api.entity.RevokedToken;
import com.amaris.hkt.auth.api.entity.User;
import com.amaris.hkt.auth.api.enums.Role;
import com.amaris.hkt.auth.api.repository.RevokedTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("RevokedTokenService Tests")
class RevokedTokenServiceImplTest {

    @Mock
    private RevokedTokenRepository revokedTokenRepository;

    @InjectMocks
    private RevokedTokenServiceImpl revokedTokenService;

    private User testUser;
    private String testToken;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .userId(1)
                .username("testuser")
                .email("test@example.com")
                .password("hashedpassword")
                .role(Role.USER)
                .build();

        testToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlhdCI6MTY0NjEwMDAwMH0.sig";
    }

    @Test
    @DisplayName("Should revoke token successfully")
    void testRevokeToken() {
        // Arrange
        long expirationTime = 86400000L;
        when(revokedTokenRepository.save(any(RevokedToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        revokedTokenService.revokeToken(testUser, testToken, expirationTime);

        // Assert
        verify(revokedTokenRepository, times(1)).save(any(RevokedToken.class));
    }

    @Test
    @DisplayName("Should return true if token is revoked")
    void testIsTokenRevoked_True() {
        // Arrange
        when(revokedTokenRepository.existsByToken(testToken)).thenReturn(true);

        // Act
        boolean isRevoked = revokedTokenService.isTokenRevoked(testToken);

        // Assert
        assertTrue(isRevoked);
        verify(revokedTokenRepository, times(1)).existsByToken(testToken);
    }

    @Test
    @DisplayName("Should return false if token is not revoked")
    void testIsTokenRevoked_False() {
        // Arrange
        when(revokedTokenRepository.existsByToken(testToken)).thenReturn(false);

        // Act
        boolean isRevoked = revokedTokenService.isTokenRevoked(testToken);

        // Assert
        assertFalse(isRevoked);
        verify(revokedTokenRepository, times(1)).existsByToken(testToken);
    }

    @Test
    @DisplayName("Should clean expired tokens")
    void testCleanExpiredTokens() {
        // Arrange
        when(revokedTokenRepository.deleteExpiredTokens(any(OffsetDateTime.class)))
                .thenReturn(5);

        // Act
        revokedTokenService.cleanExpiredTokens();

        // Assert
        verify(revokedTokenRepository, times(1)).deleteExpiredTokens(any(OffsetDateTime.class));
    }

    @Test
    @DisplayName("Should handle token revocation with null user")
    void testRevokeToken_WithValidInputs() {
        // Arrange
        long expirationTime = 604800000L; // 7 days
        when(revokedTokenRepository.save(any(RevokedToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        revokedTokenService.revokeToken(testUser, testToken, expirationTime);

        // Assert
        verify(revokedTokenRepository).save(argThat(rt -> 
            rt.getUser().equals(testUser) && 
            rt.getToken().equals(testToken)
        ));
    }
}

