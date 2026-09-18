package com.clinica.auth_server.repository;

import com.clinica.auth_server.entity.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    // Método mágico de Spring Data para buscar un usuario por su nombre
    Optional<Usuario> findByUsername(String username);
}