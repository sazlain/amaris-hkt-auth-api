package com.amaris.hkt.auth.api.controller;

import com.amaris.hkt.auth.api.dto.request.LoginRequest;
import com.amaris.hkt.auth.api.dto.request.LogoutRequest;
import com.amaris.hkt.auth.api.dto.request.RefreshTokenRequest;
import com.amaris.hkt.auth.api.dto.request.RegisterRequest;
import com.amaris.hkt.auth.api.dto.request.ValidateTokenRequest;
import com.amaris.hkt.auth.api.dto.response.AuthResponse;
import com.amaris.hkt.auth.api.dto.response.LogoutResponse;
import com.amaris.hkt.auth.api.dto.response.ValidateTokenResponse;
import com.amaris.hkt.auth.api.enums.Role;
import com.amaris.hkt.auth.api.exception.ErrorResponse;
import com.amaris.hkt.auth.api.exception.BusinessException;
import com.amaris.hkt.auth.api.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.security.access.prepost.PreAuthorize;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Registro, login, refresco de token y logout")
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "Registrar usuario",
               description = "Crea un nuevo usuario en el sistema. Roles disponibles: USER.")
    @SecurityRequirements  // este endpoint no requiere JWT
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Usuario registrado exitosamente",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Username o email ya en uso / datos inválidos",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @Operation(summary = "Iniciar sesión",
               description = "Autentica al usuario y retorna un JWT de acceso y un refresh token.")
    @SecurityRequirements  // este endpoint no requiere JWT
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login exitoso",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Credenciales inválidas o cuenta deshabilitada",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @Operation(summary = "Renovar token",
               description = "Genera un nuevo JWT usando el refresh token. No requiere enviar el JWT expirado.")
    @SecurityRequirements
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Token renovado",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Refresh token inválido, expirado o revocado",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @Operation(summary = "Cerrar sesión",
               description = "Revoca todos los refresh tokens del usuario especificado y los marca como revocados. El username debe coincidir con el usuario autenticado en el JWT.")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Sesión cerrada exitosamente",
                    content = @Content(schema = @Schema(implementation = LogoutResponse.class))),
            @ApiResponse(responseCode = "401", description = "No autorizado - JWT inválido, expirado o no proporcionado",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "400", description = "Username del request no coincide con el usuario autenticado",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/logout")
    public ResponseEntity<LogoutResponse> logout(
            @Valid @RequestBody LogoutRequest request,
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest) {
        // Validar que el JWT sea válido (userDetails no sea null)
        if (userDetails == null) {
            throw new BusinessException("Token inválido o expirado. Debes proporcionar un JWT válido");
        }
        // Validar que el username del request coincida con el usuario autenticado
        if (!userDetails.getUsername().equals(request.getUsername())) {
            throw new BusinessException("No puedes cerrar sesión de otro usuario");
        }
        
        // Extraer el JWT del header Authorization
        String authHeader = httpRequest.getHeader("Authorization");
        String jwtToken = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwtToken = authHeader.substring(7);
        }
        
        if (jwtToken == null || jwtToken.isBlank()) {
            throw new BusinessException("JWT no encontrado en el header Authorization");
        }
        
        authService.logout(request.getUsername(), jwtToken);

        // Retornar 200 con mensaje de confirmación
        LogoutResponse response = LogoutResponse.builder()
                .message("Sesión cerrada exitosamente")
                .username(request.getUsername())
                .timestamp(java.time.OffsetDateTime.now())
                .build();
        
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "Validar token",
               description = "Valida si un JWT es válido y retorna información del usuario. Útil para que otras APIs validen tokens emitidos por esta API.")
    @SecurityRequirements  // este endpoint no requiere JWT
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Validación completada (token válido o inválido)",
                    content = @Content(schema = @Schema(implementation = ValidateTokenResponse.class))),
            @ApiResponse(responseCode = "400", description = "Token requerido",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/validate-token")
    public ResponseEntity<ValidateTokenResponse> validateToken(@Valid @RequestBody ValidateTokenRequest request) {
        ValidateTokenResponse response = authService.validateToken(request.getToken());
        // Retornar 200 incluso si el token es inválido (la respuesta indica el estado)
        return ResponseEntity.ok(response);
    }
}
