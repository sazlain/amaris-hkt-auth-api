package com.amaris.hkt.auth.api.security;

import com.amaris.hkt.auth.api.entity.User;
import com.amaris.hkt.auth.api.enums.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtService Tests")
class JwtServiceTest {

    private JwtService jwtService;

    private User testUser;
    private String secretKey;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        
        // Use a valid base64 encoded secret key
        secretKey = "dGhpcy1pcy1hLXZlcnktbG9uZy1zZWNyZXQta2V5LWZvci1sb3R0ZXJ5LWFwaS1qd3Qtc2lnbmluZy0yMDI0";
        
        ReflectionTestUtils.setField(jwtService, "secretKey", secretKey);
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", 86400000L); // 24 hours

        testUser = User.builder()
                .userId(1)
                .username("testuser")
                .email("test@example.com")
                .password("hashedpassword")
                .role(Role.USER)
                .enabled(true)
                .build();
    }

    @Test
    @DisplayName("Should generate valid JWT token")
    void testGenerateToken() {
        // Act
        String token = jwtService.generateToken(testUser);

        // Assert
        assertNotNull(token);
        assertFalse(token.isEmpty());
        assertTrue(token.contains("."));
    }

    @Test
    @DisplayName("Should extract username from token")
    void testExtractUsername() {
        // Arrange
        String token = jwtService.generateToken(testUser);

        // Act
        String username = jwtService.extractUsername(token);

        // Assert
        assertEquals(testUser.getUsername(), username);
    }

    @Test
    @DisplayName("Should validate token successfully")
    void testIsTokenValid_True() {
        // Arrange
        String token = jwtService.generateToken(testUser);

        // Act
        boolean isValid = jwtService.isTokenValid(token, testUser);

        // Assert
        assertTrue(isValid);
    }

    @Test
    @DisplayName("Should return false for expired token")
    void testIsTokenValid_Expired() {
        // Arrange - generate a token with very short expiration
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", 50L); // 50ms expiration
        String token = jwtService.generateToken(testUser);
        
        // Wait longer for token to expire (add buffer for execution time)
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Act & Assert - token should be invalid (either throws ExpiredJwtException or returns false)
        try {
            boolean isValid = jwtService.isTokenValid(token, testUser);
            assertFalse(isValid);
        } catch (ExpiredJwtException e) {
            // JJWT throws ExpiredJwtException when token is expired, which is correct behavior
            assertTrue(true);
        }
    }

    @Test
    @DisplayName("Should return false for different user")
    void testIsTokenValid_DifferentUser() {
        // Arrange
        String token = jwtService.generateToken(testUser);
        User differentUser = User.builder()
                .userId(2)
                .username("differentuser")
                .email("different@example.com")
                .password("hashedpassword")
                .role(Role.ADMIN)
                .enabled(true)
                .build();

        // Act
        boolean isValid = jwtService.isTokenValid(token, differentUser);

        // Assert
        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should detect expired token")
    void testIsTokenExpired() {
        // Arrange - generate a token with very short expiration
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", 50L); // 50ms expiration
        String token = jwtService.generateToken(testUser);
        
        // Wait longer for token to expire (add buffer for execution time)
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Act & Assert - token should be expired (either throws ExpiredJwtException or returns true)
        try {
            boolean isExpired = jwtService.isTokenExpired(token);
            assertTrue(isExpired);
        } catch (ExpiredJwtException e) {
            // JJWT throws ExpiredJwtException when token is expired, which is correct behavior
            assertTrue(true);
        }
    }

    @Test
    @DisplayName("Should extract expiration date")
    void testExtractExpiration() {
        // Arrange
        String token = jwtService.generateToken(testUser);

        // Act
        Date expirationDate = jwtService.extractExpiration(token);

        // Assert
        assertNotNull(expirationDate);
        assertTrue(expirationDate.getTime() > System.currentTimeMillis());
    }

    @Test
    @DisplayName("Should extract claims from token")
    void testExtractClaim() {
        // Arrange
        String token = jwtService.generateToken(testUser);

        // Act
        String username = jwtService.extractClaim(token, Claims::getSubject);

        // Assert
        assertEquals(testUser.getUsername(), username);
    }
}











