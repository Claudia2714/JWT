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
            // Creamos los roles
            Rol rolAdmin = rolRepository.findByNombre("ROLE_ADMIN").orElseGet(() -> rolRepository.save(new Rol("ROLE_ADMIN")));
            Rol rolOperador = rolRepository.findByNombre("ROLE_OPERADOR").orElseGet(() -> rolRepository.save(new Rol("ROLE_OPERADOR")));

            // Creamos usuario Admin
            if (usuarioRepository.findByUsername("admin").isEmpty()) {
                Usuario admin = new Usuario();
                admin.setUsername("admin");
                admin.setPassword(passwordEncoder.encode("12345")); 
                admin.setRoles(Set.of(rolAdmin));
                usuarioRepository.save(admin);
                System.out.println("✅ Usuario ADMIN creado: admin / 12345");
            }

            // Creamos usuario Operador
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

    @Bean
    public org.springframework.web.servlet.config.annotation.WebMvcConfigurer corsConfigurer() {
        return new org.springframework.web.servlet.config.annotation.WebMvcConfigurer() {
            @Override
            public void addCorsMappings(org.springframework.web.servlet.config.annotation.CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:4500")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*");
            }
        };
    }
}