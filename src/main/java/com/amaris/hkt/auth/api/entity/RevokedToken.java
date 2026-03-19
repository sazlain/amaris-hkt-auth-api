package com.amaris.hkt.auth.api.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.OffsetDateTime;

@Entity
@Table(name = "revoked_tokens", indexes = {
    @Index(name = "idx_user_id", columnList = "user_id"),
    @Index(name = "idx_token", columnList = "token")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RevokedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "revoked_token_id")
    private Integer revokedTokenId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "token", nullable = false, unique = true, length = 1024)
    private String token;

    @Column(name = "expiry_date", nullable = false)
    private OffsetDateTime expiryDate;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    public boolean isExpired() {
        return OffsetDateTime.now().isAfter(expiryDate);
    }
}
