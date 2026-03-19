package com.amaris.hkt.auth.api.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Response de logout exitoso")
public class LogoutResponse {

    @Schema(description = "Mensaje de confirmación", example = "Sesión cerrada exitosamente")
    private String message;

    @Schema(description = "Username del usuario que cerró sesión", example = "juanperez")
    private String username;

    @Schema(description = "Timestamp de cuando se cerró la sesión")
    private OffsetDateTime timestamp;
}

