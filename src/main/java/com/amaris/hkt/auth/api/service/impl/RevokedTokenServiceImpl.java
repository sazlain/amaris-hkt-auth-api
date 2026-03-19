package com.amaris.hkt.auth.api.service.impl;

import com.amaris.hkt.auth.api.entity.RevokedToken;
import com.amaris.hkt.auth.api.entity.User;
import com.amaris.hkt.auth.api.repository.RevokedTokenRepository;
import com.amaris.hkt.auth.api.service.RevokedTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@Service
@RequiredArgsConstructor
public class RevokedTokenServiceImpl implements RevokedTokenService {

    private final RevokedTokenRepository revokedTokenRepository;

    @Override
    @Transactional
    public void revokeToken(User user, String jwtToken, long expirationTime) {
        RevokedToken revokedToken = RevokedToken.builder()
                .user(user)
                .token(jwtToken)
                .expiryDate(OffsetDateTime.now(ZoneOffset.UTC).plusSeconds(expirationTime / 1000))
                .build();
        
        revokedTokenRepository.save(revokedToken);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isTokenRevoked(String token) {
        return revokedTokenRepository.existsByToken(token);
    }

    @Override
    @Transactional
    public void cleanExpiredTokens() {
        int deletedCount = revokedTokenRepository.deleteExpiredTokens(OffsetDateTime.now(ZoneOffset.UTC));
        if (deletedCount > 0) {
            org.slf4j.LoggerFactory.getLogger(RevokedTokenServiceImpl.class)
                    .debug("🧹 Limpieza de tokens revocados expirados: {} registros eliminados", deletedCount);
        }
    }
}

