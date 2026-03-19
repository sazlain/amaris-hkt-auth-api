package com.amaris.hkt.auth.api.scheduler;

import com.amaris.hkt.auth.api.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Random;

@Component
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(name = "hackathon.token-revocation.enabled", havingValue = "true")
public class TokenRevocationScheduler {

    private final RefreshTokenService refreshTokenService;

    @Value("${hackathon.token-revocation.min-interval-seconds:30}")
    private long minInterval;

    @Value("${hackathon.token-revocation.max-interval-seconds:120}")
    private long maxInterval;

    private long nextRevocationTime = System.currentTimeMillis();
    private final Random random = new Random();


    @Scheduled(fixedDelay = 5000)
    public void scheduleRandomTokenRevocation() {
        long currentTime = System.currentTimeMillis();

        if (currentTime >= nextRevocationTime) {
            try {
                refreshTokenService.revokeAllTokens();
                log.warn("⚠️  HACKATHON: Revocación de tokens ejecutada");
                
                long randomDelay = (minInterval + random.nextLong((maxInterval - minInterval + 1) * 1000));
                nextRevocationTime = currentTime + randomDelay;
                
                long nextInSeconds = randomDelay / 1000;
                log.info("📅 Próxima revocación en: {} segundos", nextInSeconds);
            } catch (Exception e) {
                log.error("❌ Error durante revocación de tokens", e);
            }
        }
    }
}

