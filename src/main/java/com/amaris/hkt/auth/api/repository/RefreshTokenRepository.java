package com.amaris.hkt.auth.api.repository;

import com.amaris.hkt.auth.api.entity.RefreshToken;
import com.amaris.hkt.auth.api.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {

    Optional<RefreshToken> findByToken(String token);

    // FIX: Added clearAutomatically=true to flush the persistence context after the bulk UPDATE,
    // preventing stale entity state from being used in the same transaction after revoking tokens.
    @Modifying(clearAutomatically = true)
    @Query("UPDATE RefreshToken r SET r.revoked = true WHERE r.user = :user")
    void revokeAllUserTokens(@Param("user") User user);

    @Modifying(clearAutomatically = true)
    @Query("DELETE FROM RefreshToken r WHERE r.user = :user")
    void deleteAllByUser(@Param("user") User user);

    @Modifying(clearAutomatically = true)
    @Query("UPDATE RefreshToken r SET r.revoked = true WHERE r.revoked = false")
    int revokeAllTokens();
}
