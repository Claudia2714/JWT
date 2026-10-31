package com.clinica.auth_server.controller;

import com.clinica.auth_server.dto.AuthRequest;
import com.clinica.auth_server.service.JwtService;
import com.clinica.auth_server.service.LoginAttemptService;
import com.clinica.auth_server.service.RateLimitService;
import com.clinica.auth_server.service.TurnstileService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/auth")
public class AuthController {

    // ── Mensaje genérico para TODOS los errores de autenticación ────────────
    // Esto previene la enumeración de usuarios y revela el menor detalle posible.
    private static final String ERROR_GENERICO = "Credenciales inválidas o acceso denegado.";

    private final AuthenticationManager authenticationManager;
    private final JwtService            jwtService;
    private final LoginAttemptService   loginAttemptService;
    private final RateLimitService      rateLimitService;
    private final TurnstileService      turnstileService;

    public AuthController(AuthenticationManager authenticationManager,
                          JwtService jwtService,
                          LoginAttemptService loginAttemptService,
                          RateLimitService rateLimitService,
                          TurnstileService turnstileService) {
        this.authenticationManager = authenticationManager;
        this.jwtService            = jwtService;
        this.loginAttemptService   = loginAttemptService;
        this.rateLimitService      = rateLimitService;
        this.turnstileService      = turnstileService;
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody AuthRequest request,
                                        HttpServletRequest httpRequest) {

        // ── Paso 1: Rate Limiting ────────────────────────────────────────────
        // Obtiene la IP real del cliente (considera proxies/load balancers)
        String clientIp = obtenerIpCliente(httpRequest);
        if (!rateLimitService.intentarConsumir(clientIp)) {
            // 429 Too Many Requests — respuesta estándar para rate limiting
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header("Retry-After", "60")
                    .body("Demasiadas solicitudes. Espera un momento antes de intentar de nuevo.");
        }

        // ── Paso 2: Validación de CAPTCHA (Cloudflare Turnstile) ─────────────
        boolean captchaValido = turnstileService.validarToken(
                request.getTurnstileToken(), clientIp);
        if (!captchaValido) {
            // Retornamos el mismo error genérico para no revelar por qué falló
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ERROR_GENERICO);
        }

        // ── Paso 3: Verificar bloqueo temporal de cuenta ─────────────────────
        // Nota: si el usuario no existe, estaBloqueado() devuelve false
        // y el flujo continuará hasta fallar en autenticación (paso 4).
        if (loginAttemptService.estaBloqueado(request.getUsername())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ERROR_GENERICO);
        }

        // ── Paso 4: Autenticación con Spring Security ─────────────────────────
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            // ✅ Login exitoso → resetear contador de intentos fallidos
            loginAttemptService.resetearIntentos(request.getUsername());

            // Generar y devolver el JWT firmado con RSA
            List<String> roles = authentication.getAuthorities().stream()
                    .map(org.springframework.security.core.GrantedAuthority::getAuthority)
                    .toList();

            String token = jwtService.generateToken(authentication.getName(), roles);
            return ResponseEntity.ok(token);

        } catch (BadCredentialsException e) {
            // ❌ Credenciales incorrectas → registrar fallo
            loginAttemptService.registrarFallo(request.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ERROR_GENERICO);

        } catch (Exception e) {
            // Cualquier otro error también responde genéricamente
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ERROR_GENERICO);
        }
    }

    /**
     * Extrae la IP real del cliente considerando proxies y load balancers.
     * El header X-Forwarded-For es estándar cuando hay un reverse proxy (Nginx, CloudFlare).
     */
    private String obtenerIpCliente(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            // El header puede contener múltiples IPs: "client, proxy1, proxy2"
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}