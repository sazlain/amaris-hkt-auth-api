package com.amaris.hkt.auth.api.service;

import com.amaris.hkt.auth.api.dto.request.LoginRequest;
import com.amaris.hkt.auth.api.dto.request.RefreshTokenRequest;
import com.amaris.hkt.auth.api.dto.request.RegisterRequest;
import com.amaris.hkt.auth.api.dto.response.AuthResponse;
import com.amaris.hkt.auth.api.dto.response.ValidateTokenResponse;
import com.amaris.hkt.auth.api.enums.Role;

public interface AuthService {
    AuthResponse register(RegisterRequest request);
    AuthResponse login(LoginRequest request);
    AuthResponse refreshToken(RefreshTokenRequest request);
    void logout(String username, String jwtToken);
    AuthResponse createUserWithRole(RegisterRequest request, Role role);
    ValidateTokenResponse validateToken(String token);
}
