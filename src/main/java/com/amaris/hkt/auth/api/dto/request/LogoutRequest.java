package com.amaris.hkt.auth.api.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Request para cerrar sesión del usuario")
public class LogoutRequest {

    @NotBlank(message = "El username es obligatorio")
    @Schema(description = "Username del usuario a cerrar sesión", example = "juanperez", requiredMode = Schema.RequiredMode.REQUIRED)
    private String username;
}

