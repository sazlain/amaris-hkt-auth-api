package com.amaris.hkt.auth.api.service.impl;

import com.amaris.hkt.auth.api.entity.User;
import com.amaris.hkt.auth.api.enums.Role;
import com.amaris.hkt.auth.api.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserDetailsService Tests")
class UserDetailsServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserDetailsServiceImpl userDetailsService;

    private User testUser;

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
    }

    @Test
    @DisplayName("Should load user by username successfully")
    void testLoadUserByUsername_Success() {
        // Arrange
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // Act
        UserDetails userDetails = userDetailsService.loadUserByUsername("testuser");

        // Assert
        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        assertEquals("hashedpassword", userDetails.getPassword());
        assertTrue(userDetails.isEnabled());
        assertTrue(userDetails.isAccountNonExpired());
        assertTrue(userDetails.isAccountNonLocked());
        assertTrue(userDetails.isCredentialsNonExpired());

        // Verify that the role is present in authorities
        boolean hasUserRole = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(auth -> auth.equals("ROLE_USER"));
        assertTrue(hasUserRole);

        verify(userRepository).findByUsername("testuser");
    }

    @Test
    @DisplayName("Should throw exception when user not found")
    void testLoadUserByUsername_UserNotFound() {
        // Arrange
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(UsernameNotFoundException.class, () -> 
            userDetailsService.loadUserByUsername("nonexistent"));

        verify(userRepository).findByUsername("nonexistent");
    }

    @Test
    @DisplayName("Should load admin user with correct authorities")
    void testLoadUserByUsername_AdminUser() {
        // Arrange
        User adminUser = User.builder()
                .userId(2)
                .username("admin")
                .email("admin@example.com")
                .password("hashedpassword")
                .role(Role.ADMIN)
                .enabled(true)
                .build();

        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(adminUser));

        // Act
        UserDetails userDetails = userDetailsService.loadUserByUsername("admin");

        // Assert
        assertNotNull(userDetails);
        assertEquals("admin", userDetails.getUsername());
        
        boolean hasAdminRole = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(auth -> auth.equals("ROLE_ADMIN"));
        assertTrue(hasAdminRole);

        verify(userRepository).findByUsername("admin");
    }

    @Test
    @DisplayName("Should load disabled user")
    void testLoadUserByUsername_DisabledUser() {
        // Arrange
        User disabledUser = User.builder()
                .userId(3)
                .username("disabled")
                .email("disabled@example.com")
                .password("hashedpassword")
                .role(Role.USER)
                .enabled(false)
                .build();

        when(userRepository.findByUsername("disabled")).thenReturn(Optional.of(disabledUser));

        // Act
        UserDetails userDetails = userDetailsService.loadUserByUsername("disabled");

        // Assert
        assertNotNull(userDetails);
        assertFalse(userDetails.isEnabled());

        verify(userRepository).findByUsername("disabled");
    }

    @Test
    @DisplayName("Should handle exception with message")
    void testLoadUserByUsername_ExceptionMessage() {
        // Arrange
        String username = "testuser";
        when(userRepository.findByUsername(username)).thenReturn(Optional.empty());

        // Act & Assert
        UsernameNotFoundException exception = assertThrows(UsernameNotFoundException.class, () -> 
            userDetailsService.loadUserByUsername(username));

        assertTrue(exception.getMessage().contains(username));
    }
}

