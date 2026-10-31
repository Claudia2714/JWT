package com.clinica.auth_server;

import com.clinica.auth_server.entity.Rol;
import com.clinica.auth_server.entity.Usuario;
import com.clinica.auth_server.repository.RolRepository;
import com.clinica.auth_server.repository.UsuarioRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@SpringBootApplication
public class AuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }

    /**
     * Inicializa la base de datos con roles y usuarios de prueba.
     * Este código se ejecuta automáticamente al arrancar el servidor.
     * Las condiciones "orElseGet" y "findByUsername(...).isEmpty()" evitan duplicados
     * en arranques posteriores (idempotente).
     */
    @Bean
    CommandLineRunner initDatabase(UsuarioRepository usuarioRepository,
                                   RolRepository rolRepository,
                                   PasswordEncoder passwordEncoder) {
        return args -> {
            // Crear roles (si no existen)
            Rol rolAdmin    = rolRepository.findByNombre("ROLE_ADMIN")
                    .orElseGet(() -> rolRepository.save(new Rol("ROLE_ADMIN")));
            Rol rolOperador = rolRepository.findByNombre("ROLE_OPERADOR")
                    .orElseGet(() -> rolRepository.save(new Rol("ROLE_OPERADOR")));

            // Crear usuario Admin (si no existe)
            if (usuarioRepository.findByUsername("admin").isEmpty()) {
                Usuario admin = new Usuario();
                admin.setUsername("admin");
                admin.setPassword(passwordEncoder.encode("12345"));
                admin.setRoles(Set.of(rolAdmin));
                usuarioRepository.save(admin);
                System.out.println("✅ Usuario ADMIN creado: admin / 12345");
            }

            // Crear usuario Operador (si no existe)
            if (usuarioRepository.findByUsername("operador").isEmpty()) {
                Usuario operador = new Usuario();
                operador.setUsername("operador");
                operador.setPassword(passwordEncoder.encode("12345"));
                operador.setRoles(Set.of(rolOperador));
                usuarioRepository.save(operador);
                System.out.println("✅ Usuario OPERADOR creado: operador / 12345");
            }
        };
    }

    // NOTA: La configuración CORS fue movida a SecurityConfig.java
    // para centralizar toda la configuración de seguridad en un solo lugar.
}