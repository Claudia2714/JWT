package com.clinica.auth_server.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Map;

/**
 * Servicio de validación de Cloudflare Turnstile (CAPTCHA).
 *
 * Turnstile es la alternativa de Cloudflare a reCAPTCHA v3.
 * El widget del frontend genera un token efímero que DEBE ser
 * validado en el backend contra la API de Cloudflare.
 *
 * Documentación: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
 *
 * Configuración requerida en application.properties:
 *   turnstile.secret-key=TU_SECRET_KEY_DE_CLOUDFLARE
 */
@Service
public class TurnstileService {

    private static final String TURNSTILE_VERIFY_URL =
            "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    /** Clave secreta de prueba oficial de Cloudflare (Always passes) */
    private static final String DUMMY_TEST_SECRET_KEY = "1x0000000000000000000000000000000AA";

    /** Secret key del dashboard de Cloudflare (cargada desde variable de entorno) */
    @Value("${turnstile.secret-key}")
    private String secretKey;

    private final RestTemplate restTemplate;

    public TurnstileService() {
        // Timeout estricto de 3 segundos para conexión y lectura
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(3));
        factory.setReadTimeout(Duration.ofSeconds(3));
        this.restTemplate = new RestTemplate(factory);
    }

    /**
     * Valida el token generado por el widget de Turnstile en el frontend.
     *
     * @param token    El cf-turnstile-response enviado por el frontend
     * @param clientIp IP del cliente (opcional pero recomendada por Cloudflare)
     * @return true si el token es válido según Cloudflare o bypass de prueba
     */
    public boolean validarToken(String token, String clientIp) {
        // ── Bypass local para pruebas y desarrollo ─────────────────────────────
        // Si la clave es la clave de prueba de Cloudflare, validamos exitosamente sin llamada HTTP
        if (DUMMY_TEST_SECRET_KEY.equalsIgnoreCase(secretKey != null ? secretKey.trim() : "")) {
            System.out.println("[TURNSTILE] Bypass local activo (clave de prueba detectada). Validación aprobada.");
            return true;
        }

        // Si no hay token en entorno real, falla directamente
        if (token == null || token.isBlank()) {
            System.err.println("[TURNSTILE] Token no proporcionado o vacío.");
            return false;
        }

        try {
            // Cloudflare espera un POST con form-data (no JSON)
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("secret",   secretKey);
            body.add("response", token);
            if (clientIp != null && !clientIp.isBlank()) {
                body.add("remoteip", clientIp);
            }

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(
                    TURNSTILE_VERIFY_URL, request, Map.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                // La respuesta tiene { "success": true/false, "error-codes": [...] }
                Object success = response.getBody().get("success");
                return Boolean.TRUE.equals(success);
            }
        } catch (ResourceAccessException e) {
            System.err.println("[TURNSTILE] Timeout / Error de conexión al validar con Cloudflare (límite 3s excedido): " + e.getMessage());
            return false;
        } catch (RestClientException e) {
            System.err.println("[TURNSTILE] Error HTTP al validar token en Cloudflare: " + e.getMessage());
            return false;
        } catch (Exception e) {
            System.err.println("[TURNSTILE] Error inesperado al validar token: " + e.getMessage());
            return false;
        }

        return false;
    }
}
