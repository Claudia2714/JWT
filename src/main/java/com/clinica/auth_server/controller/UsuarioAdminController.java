package com.clinica.auth_server.controller;

import com.clinica.auth_server.dto.UsuarioDto;
import com.clinica.auth_server.entity.Rol;
import com.clinica.auth_server.entity.Usuario;
import com.clinica.auth_server.repository.RolRepository;
import com.clinica.auth_server.repository.UsuarioRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/usuarios")
public class UsuarioAdminController {

    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final PasswordEncoder passwordEncoder;

    public UsuarioAdminController(UsuarioRepository usuarioRepository,
                                  RolRepository rolRepository,
                                  PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.rolRepository = rolRepository;
        this.passwordEncoder = passwordEncoder;
    }

    private UsuarioDto mapearDto(Usuario u) {
        UsuarioDto dto = new UsuarioDto();
        dto.setId(u.getId());
        dto.setUsername(u.getUsername());
        dto.setIntentosFallidos(u.getIntentosFallidos());
        boolean bloqueado = u.getBloqueadoHasta() != null && LocalDateTime.now().isBefore(u.getBloqueadoHasta());
        dto.setBloqueado(bloqueado);
        if (u.getRoles() != null) {
            dto.setRoles(u.getRoles().stream().map(Rol::getNombre).collect(Collectors.toSet()));
        } else {
            dto.setRoles(Collections.emptySet());
        }
        return dto;
    }

    @GetMapping
    public List<UsuarioDto> listar() {
        return usuarioRepository.findAll().stream().map(this::mapearDto).collect(Collectors.toList());
    }

    @GetMapping("/roles")
    public List<Rol> listarRoles() {
        return rolRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<UsuarioDto> obtenerPorId(@PathVariable Long id) {
        return usuarioRepository.findById(id)
                .map(this::mapearDto)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<?> crear(@RequestBody UsuarioDto dto) {
        if (dto.getUsername() == null || dto.getUsername().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "El nombre de usuario es obligatorio"));
        }
        if (usuarioRepository.findByUsername(dto.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "El usuario ya existe"));
        }
        if (dto.getPassword() == null || dto.getPassword().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "La contraseña es obligatoria"));
        }

        Usuario usuario = new Usuario();
        usuario.setUsername(dto.getUsername().trim());
        usuario.setPassword(passwordEncoder.encode(dto.getPassword()));
        usuario.setIntentosFallidos(0);
        usuario.setBloqueadoHasta(null);

        Set<Rol> roles = new HashSet<>();
        if (dto.getRoles() != null && !dto.getRoles().isEmpty()) {
            for (String rName : dto.getRoles()) {
                rolRepository.findByNombre(rName).ifPresent(roles::add);
            }
        }
        if (roles.isEmpty()) {
            rolRepository.findByNombre("ROLE_OPERADOR").ifPresent(roles::add);
        }
        usuario.setRoles(roles);

        Usuario guardado = usuarioRepository.save(usuario);
        return new ResponseEntity<>(mapearDto(guardado), HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> actualizar(@PathVariable Long id, @RequestBody UsuarioDto dto) {
        return usuarioRepository.findById(id).map(usuario -> {
            if (dto.getUsername() != null && !dto.getUsername().isBlank()) {
                usuario.setUsername(dto.getUsername().trim());
            }
            if (dto.getPassword() != null && !dto.getPassword().isBlank()) {
                usuario.setPassword(passwordEncoder.encode(dto.getPassword()));
            }
            if (dto.getRoles() != null) {
                Set<Rol> roles = new HashSet<>();
                for (String rName : dto.getRoles()) {
                    rolRepository.findByNombre(rName).ifPresent(roles::add);
                }
                usuario.setRoles(roles);
            }
            Usuario actualizado = usuarioRepository.save(usuario);
            return ResponseEntity.ok(mapearDto(actualizado));
        }).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/desbloquear")
    public ResponseEntity<?> desbloquear(@PathVariable Long id) {
        return usuarioRepository.findById(id).map(usuario -> {
            usuario.setIntentosFallidos(0);
            usuario.setBloqueadoHasta(null);
            usuarioRepository.save(usuario);
            return ResponseEntity.ok(Map.of("mensaje", "Usuario desbloqueado exitosamente"));
        }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> eliminar(@PathVariable Long id) {
        usuarioRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}
