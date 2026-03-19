package com.amaris.hkt.auth.api.dto.response;

import com.amaris.hkt.auth.api.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;
import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ValidateTokenResponse {
    /**
     * Indica si el token es válido o no
     */
    private boolean valid;

    /**
     * Mensaje descriptivo sobre la validez del token
     */
    private String message;

    /**
     * Username del usuario propietario del token (si es válido)
     */
    private String username;

    /**
     * Email del usuario propietario del token (si es válido)
     */
    private String email;

    /**
     * Rol del usuario propietario del token (si es válido)
     */
    private Role role;

    /**
     * Fecha de expiración del token
     */
    private Date expiresAt;

    /**
     * Timestamp de la validación
     */
    private OffsetDateTime validatedAt;
}

