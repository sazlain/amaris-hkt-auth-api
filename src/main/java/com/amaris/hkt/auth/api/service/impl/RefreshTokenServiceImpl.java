package com.amaris.hkt.auth.api.service.impl;

import com.amaris.hkt.auth.api.entity.RefreshToken;
import com.amaris.hkt.auth.api.entity.User;
import com.amaris.hkt.auth.api.exception.BusinessException;
import com.amaris.hkt.auth.api.repository.RefreshTokenRepository;
import com.amaris.hkt.auth.api.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    @Override
    @Transactional
    public RefreshToken createRefreshToken(User user) {
        // Revocar tokens anteriores del usuario
        revokeAllUserTokens(user);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(OffsetDateTime.now().plusSeconds(refreshExpiration / 1000))
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Override
    @Transactional(readOnly = true)
    public RefreshToken verifyRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new BusinessException("Refresh token inválido o no encontrado"));

        if (refreshToken.getRevoked()) {
            throw new BusinessException("Refresh token revocado");
        }

        if (refreshToken.isExpired()) {
            throw new BusinessException("Refresh token expirado. Por favor inicie sesión nuevamente");
        }

        return refreshToken;
    }

    @Override
    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllUserTokens(user);
    }

    @Override
    @Transactional
    public void revokeAllTokens() {
        int revokedCount = refreshTokenRepository.revokeAllTokens();
        org.slf4j.LoggerFactory.getLogger(RefreshTokenServiceImpl.class)
                .warn("🚨 HACKATHON: Todos los tokens revocados. Total: {}", revokedCount);
    }
}
