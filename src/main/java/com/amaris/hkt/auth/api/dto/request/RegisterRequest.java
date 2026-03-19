package com.amaris.hkt.auth.api.dto.request;

import com.amaris.hkt.auth.api.enums.Role;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.Data;

@Data
@Schema(description = "Datos para registrar un nuevo usuario")
public class RegisterRequest {

    @Schema(description = "Nombre de usuario único para el login", example = "juanperez",
            requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "El username es obligatorio")
    @Size(min = 4, max = 50, message = "El username debe tener entre 4 y 50 caracteres")
    private String username;

    @Schema(description = "Correo electrónico del usuario",
            example = "juan@email.com", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "El email es obligatorio")
    @Email(message = "Email inválido")
    private String email;

    @Schema(description = "Contraseña (mín. 8 caracteres, 1 mayúscula, 1 número)",
            example = "Segura123!", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 8, message = "La contraseña debe tener mínimo 8 caracteres")
    @Pattern(regexp = "^(?=.*[A-Z])(?=.*\\d).+$",
             message = "La contraseña debe contener al menos una mayúscula y un número")
    private String password;

    @Schema(description = "Rol del usuario en el sistema", example = "USER",
            allowableValues = {"ADMIN", "USER"})
    private Role role = Role.USER;
}
