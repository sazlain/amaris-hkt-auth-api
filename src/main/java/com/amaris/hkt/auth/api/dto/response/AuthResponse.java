package com.amaris.hkt.auth.api.dto.response;

import com.amaris.hkt.auth.api.enums.Role;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @Builder @NoArgsConstructor @AllArgsConstructor
@Schema(description = "Respuesta de autenticación con tokens JWT")
public class AuthResponse {

    @Schema(description = "Token JWT de acceso", example = "eyJhbGciOiJIUzI1NiJ9...")
    private String accessToken;

    @Schema(description = "Token de refresco para renovar el JWT")
    private String refreshToken;

    @Schema(description = "Tipo de token", example = "Bearer")
    @Builder.Default
    private String tokenType = "Bearer";

    @Schema(description = "Tiempo de expiración del access token en ms", example = "86400000")
    private Long expiresIn;

    @Schema(description = "Datos del usuario autenticado")
    private UserInfoResponse user;

    @Data @Builder @NoArgsConstructor @AllArgsConstructor
    @Schema(description = "Información del usuario autenticado")
    public static class UserInfoResponse {
        @Schema(example = "1")                   private Integer userId;
        @Schema(example = "juanperez")           private String  username;
        @Schema(example = "juan@email.com")      private String  email;
        @Schema(example = "CUSTOMER")            private Role    role;
    }
}


