package com.amaris.hkt.auth.api.service;

import com.amaris.hkt.auth.api.entity.RefreshToken;
import com.amaris.hkt.auth.api.entity.User;

public interface RefreshTokenService {
    RefreshToken createRefreshToken(User user);
    RefreshToken verifyRefreshToken(String token);
    void revokeAllUserTokens(User user);
    void revokeAllTokens();
}
