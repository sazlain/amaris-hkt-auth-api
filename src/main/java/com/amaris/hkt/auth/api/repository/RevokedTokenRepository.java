package com.amaris.hkt.auth.api.repository;

import com.amaris.hkt.auth.api.entity.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;

@Repository
public interface RevokedTokenRepository extends JpaRepository<RevokedToken, Integer> {

    boolean existsByToken(String token);

    @Modifying(clearAutomatically = true)
    @Query("DELETE FROM RevokedToken r WHERE r.expiryDate < :now")
    int deleteExpiredTokens(@Param("now") OffsetDateTime now);
}

