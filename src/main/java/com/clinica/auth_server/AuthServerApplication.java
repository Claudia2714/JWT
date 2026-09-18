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

    // Este código se ejecuta automáticamente al darle "Play" al proyecto
    @Bean
    CommandLineRunner initDatabase(UsuarioRepository usuarioRepository, RolRepository rolRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            // Solo crea el usuario si la base de datos está vacía
            if (usuarioRepository.findByUsername("admin").isEmpty()) {
                Rol rolAdmin = new Rol("ROLE_ADMIN");
                rolRepository.save(rolAdmin);

                Usuario admin = new Usuario();
                admin.setUsername("admin");
                // Encriptamos la contraseña "12345"
                admin.setPassword(passwordEncoder.encode("12345")); 
                admin.setRoles(Set.of(rolAdmin));

                usuarioRepository.save(admin);
                System.out.println("✅ Usuario de prueba creado: admin / 12345");
            }
        };
    }
}