package com.amaris.hkt.auth.api.service;

import com.amaris.hkt.auth.api.entity.User;

public interface RevokedTokenService {
    void revokeToken(User user, String jwtToken, long expirationTime);
    boolean isTokenRevoked(String token);
    void cleanExpiredTokens();
}

