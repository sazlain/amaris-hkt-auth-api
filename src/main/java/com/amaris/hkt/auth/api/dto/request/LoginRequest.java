package com.amaris.hkt.auth.api.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Credenciales para iniciar sesión")
public class LoginRequest {

    @Schema(description = "Nombre de usuario", example = "admin", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "El username es obligatorio")
    private String username;

    @Schema(description = "Contraseña", example = "Admin123!", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "La contraseña es obligatoria")
    private String password;
}
