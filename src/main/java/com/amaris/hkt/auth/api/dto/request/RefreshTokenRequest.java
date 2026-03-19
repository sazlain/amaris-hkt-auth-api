package com.amaris.hkt.auth.api.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Token de refresco para renovar el JWT")
public class RefreshTokenRequest {

    @Schema(description = "Refresh token obtenido en el login", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "El refresh token es obligatorio")
    private String refreshToken;
}
