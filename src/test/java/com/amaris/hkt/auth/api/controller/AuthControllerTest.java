package com.amaris.hkt.auth.api.controller;

import com.amaris.hkt.auth.api.dto.request.LoginRequest;
import com.amaris.hkt.auth.api.dto.request.LogoutRequest;
import com.amaris.hkt.auth.api.dto.request.RefreshTokenRequest;
import com.amaris.hkt.auth.api.dto.request.RegisterRequest;
import com.amaris.hkt.auth.api.dto.request.ValidateTokenRequest;
import com.amaris.hkt.auth.api.dto.response.AuthResponse;
import com.amaris.hkt.auth.api.dto.response.ValidateTokenResponse;
import com.amaris.hkt.auth.api.enums.Role;
import com.amaris.hkt.auth.api.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthController Tests")
class AuthControllerTest {

    @Mock
    private AuthService authService;

    @InjectMocks
    private AuthController authController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(authController).build();
        objectMapper = new ObjectMapper();
    }

    @Test
    @DisplayName("Should register user successfully")
    void testRegister_Success() throws Exception {
        // Arrange
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername("newuser");
        registerRequest.setEmail("newuser@example.com");
        registerRequest.setPassword("Password123!");
        registerRequest.setRole(Role.USER);

        AuthResponse authResponse = new AuthResponse();
        authResponse.setAccessToken("jwt_token");
        authResponse.setRefreshToken("refresh_token");
        authResponse.setExpiresIn(86400L);

        when(authService.register(any(RegisterRequest.class))).thenReturn(authResponse);

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").value("jwt_token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh_token"));

        verify(authService).register(any(RegisterRequest.class));
    }

    @Test
    @DisplayName("Should login user successfully")
    void testLogin_Success() throws Exception {
        // Arrange
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("Password123!");

        AuthResponse authResponse = new AuthResponse();
        authResponse.setAccessToken("jwt_token");
        authResponse.setRefreshToken("refresh_token");
        authResponse.setExpiresIn(86400L);

        when(authService.login(any(LoginRequest.class))).thenReturn(authResponse);

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("jwt_token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh_token"));

        verify(authService).login(any(LoginRequest.class));
    }

    @Test
    @DisplayName("Should refresh token successfully")
    void testRefreshToken_Success() throws Exception {
        // Arrange
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();
        refreshTokenRequest.setRefreshToken("old_refresh_token");

        AuthResponse authResponse = new AuthResponse();
        authResponse.setAccessToken("new_jwt_token");
        authResponse.setRefreshToken("new_refresh_token");
        authResponse.setExpiresIn(86400L);

        when(authService.refreshToken(any(RefreshTokenRequest.class))).thenReturn(authResponse);

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/refresh-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshTokenRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new_jwt_token"))
                .andExpect(jsonPath("$.refreshToken").value("new_refresh_token"));

        verify(authService).refreshToken(any(RefreshTokenRequest.class));
    }

    @Test
    @Disabled("MockMvc standaloneSetup no soporta @AuthenticationPrincipal - requiere WebApplicationContext")
    @DisplayName("Should logout user successfully")
    void testLogout_Success() throws Exception {
        // Arrange
        LogoutRequest logoutRequest = new LogoutRequest();
        logoutRequest.setUsername("testuser");
        
        doNothing().when(authService).logout(anyString(), anyString());
        
        // Create a UserDetails for the principal
        org.springframework.security.core.userdetails.User userDetails = 
            new org.springframework.security.core.userdetails.User("testuser", "", new java.util.ArrayList<>());

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(logoutRequest))
                .header("Authorization", "Bearer jwt_token")
                .principal(new UsernamePasswordAuthenticationToken(userDetails, null, new java.util.ArrayList<>())))
                .andExpect(status().isOk());

        verify(authService).logout(anyString(), anyString());
    }

    @Test
    @DisplayName("Should validate token successfully")
    void testValidateToken_Success() throws Exception {
        // Arrange
        String token = "jwt_token";
        ValidateTokenRequest validateTokenRequest = new ValidateTokenRequest();
        validateTokenRequest.setToken(token);
        
        ValidateTokenResponse validateTokenResponse = new ValidateTokenResponse();
        validateTokenResponse.setValid(true);
        validateTokenResponse.setUsername("testuser");
        validateTokenResponse.setMessage("Token válido");

        when(authService.validateToken(token)).thenReturn(validateTokenResponse);

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/validate-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(validateTokenRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.username").value("testuser"));

        verify(authService).validateToken(token);
    }

    @Test
    @DisplayName("Should return invalid for invalid token")
    void testValidateToken_Invalid() throws Exception {
        // Arrange
        String token = "invalid_token";
        ValidateTokenRequest validateTokenRequest = new ValidateTokenRequest();
        validateTokenRequest.setToken(token);
        
        ValidateTokenResponse validateTokenResponse = new ValidateTokenResponse();
        validateTokenResponse.setValid(false);
        validateTokenResponse.setMessage("Token inválido o expirado");

        when(authService.validateToken(token)).thenReturn(validateTokenResponse);

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/validate-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(validateTokenRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));

        verify(authService).validateToken(token);
    }

    @Test
    @DisplayName("Should handle missing token in validate endpoint")
    void testValidateToken_MissingToken() throws Exception {
        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/validate-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should handle invalid request body in register")
    void testRegister_InvalidRequest() throws Exception {
        // Arrange
        String invalidRequest = "{}";

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidRequest))
                .andExpect(status().isBadRequest());

        verify(authService, never()).register(any(RegisterRequest.class));
    }

    @Test
    @DisplayName("Should handle invalid request body in login")
    void testLogin_InvalidRequest() throws Exception {
        // Arrange
        String invalidRequest = "{}";

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidRequest))
                .andExpect(status().isBadRequest());

        verify(authService, never()).login(any(LoginRequest.class));
    }
}














