package com.clinica.auth_server.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Servicio de Rate Limiting con Bucket4j — algoritmo "Token Bucket".
 *
 * Regla configurada:
 *   - Máximo 10 peticiones por minuto por IP.
 *   - Si se excede → el controlador responderá 429 Too Many Requests.
 *
 * El estado de cada bucket se guarda en un ConcurrentHashMap en memoria.
 * Esto es suficiente para un solo servidor; si se escala horizontalmente,
 * se puede migrar a bucket4j-redis para compartir el estado entre instancias.
 */
@Service
public class RateLimitService {

    private static final int  MAX_PETICIONES_POR_MINUTO = 10;

    /**
     * Un bucket por IP de cliente. ConcurrentHashMap es thread-safe
     * para acceso concurrente desde múltiples hilos de solicitudes.
     */
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    /**
     * Verifica si la IP tiene capacidad disponible (consume 1 token).
     *
     * @param clientIp dirección IP del cliente
     * @return true si la petición debe procesarse, false si debe rechazarse con 429
     */
    public boolean intentarConsumir(String clientIp) {
        Bucket bucket = buckets.computeIfAbsent(clientIp, this::crearNuevoBucket);
        return bucket.tryConsume(1);
    }

    /**
     * Crea un nuevo bucket con el límite configurado.
     * Refill.greedy recarga tokens de forma continua (no en bloques).
     */
    private Bucket crearNuevoBucket(String clientIp) {
        Bandwidth limite = Bandwidth.classic(
                MAX_PETICIONES_POR_MINUTO,
                Refill.greedy(MAX_PETICIONES_POR_MINUTO, Duration.ofMinutes(1))
        );
        return Bucket.builder()
                .addLimit(limite)
                .build();
    }
}
