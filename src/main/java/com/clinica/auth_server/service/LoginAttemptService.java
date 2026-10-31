package com.clinica.auth_server.service;

import com.clinica.auth_server.entity.Usuario;
import com.clinica.auth_server.repository.UsuarioRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Servicio de Control de Intentos Fallidos y Bloqueo Temporal.
 *
 * Reglas implementadas:
 *  - Máximo 5 intentos fallidos consecutivos.
 *  - Al superar el límite → bloqueo por 15 minutos.
 *  - El mensaje de error SIEMPRE es genérico (no revela si el usuario existe).
 *  - El conteo se resetea en cada login exitoso.
 */
@Service
public class LoginAttemptService {

    private static final int MAX_INTENTOS     = 5;
    private static final int MINUTOS_BLOQUEO  = 15;

    private final UsuarioRepository usuarioRepository;

    public LoginAttemptService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    /**
     * Comprueba si la cuenta del usuario está actualmente bloqueada.
     * Si el bloqueo ya expiró, lo limpia automáticamente.
     *
     * @param username nombre de usuario a verificar
     * @return true si la cuenta está bloqueada y el bloqueo aún no expiró
     */
    @Transactional
    public boolean estaBloqueado(String username) {
        Optional<Usuario> opt = usuarioRepository.findByUsername(username);
        if (opt.isEmpty()) {
            // No revelamos si el usuario existe o no. Devolvemos false
            // para que el AuthController siga adelante y falle en autenticación.
            return false;
        }
        Usuario usuario = opt.get();
        LocalDateTime bloqueadoHasta = usuario.getBloqueadoHasta();

        if (bloqueadoHasta == null) {
            return false; // nunca fue bloqueado
        }

        if (LocalDateTime.now().isAfter(bloqueadoHasta)) {
            // El bloqueo expiró → limpiamos el estado
            usuario.setIntentosFallidos(0);
            usuario.setBloqueadoHasta(null);
            usuarioRepository.save(usuario);
            return false;
        }

        return true; // sigue bloqueado
    }

    /**
     * Registra un intento fallido. Si se alcanza el máximo, bloquea la cuenta.
     *
     * @param username nombre de usuario que falló
     */
    @Transactional
    public void registrarFallo(String username) {
        // Si el usuario no existe, no hacemos nada (evitamos enumerar usuarios)
        Optional<Usuario> opt = usuarioRepository.findByUsername(username);
        if (opt.isEmpty()) return;

        Usuario usuario = opt.get();
        int nuevosIntentos = usuario.getIntentosFallidos() + 1;
        usuario.setIntentosFallidos(nuevosIntentos);

        if (nuevosIntentos >= MAX_INTENTOS) {
            // Bloquear cuenta por MINUTOS_BLOQUEO minutos
            usuario.setBloqueadoHasta(LocalDateTime.now().plusMinutes(MINUTOS_BLOQUEO));
            System.out.printf("[SEGURIDAD] Cuenta '%s' bloqueada por %d min tras %d intentos fallidos%n",
                    username, MINUTOS_BLOQUEO, nuevosIntentos);
        }

        usuarioRepository.save(usuario);
    }

    /**
     * Resetea el contador de intentos fallidos tras un login exitoso.
     *
     * @param username nombre de usuario que autenticó correctamente
     */
    @Transactional
    public void resetearIntentos(String username) {
        usuarioRepository.findByUsername(username).ifPresent(usuario -> {
            usuario.setIntentosFallidos(0);
            usuario.setBloqueadoHasta(null);
            usuarioRepository.save(usuario);
        });
    }
}
