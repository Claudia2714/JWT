package com.clinica.auth_server.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Service
public class JwtService {

    // 1. Método para leer y preparar la llave privada RSA
    private PrivateKey getPrivateKey() throws Exception {
        // Lee el archivo directamente desde tu carpeta src/main/resources
        InputStream inputStream = new ClassPathResource("private_pkcs8.pem").getInputStream();
        String keyString = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);

        // Limpia el texto eliminando encabezados, pies de página y saltos de línea
        String privateKeyPEM = keyString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        // Decodifica la base 64 y crea el objeto PrivateKey de Java
        byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    // 2. Método para generar y firmar el JWT
    public String generateToken(String username, java.util.List<String> roles) {
        try {
            return Jwts.builder()
                    .claim("roles", roles) // <-- Empacamos los roles aquí
                    .setSubject(username)
                    .setIssuedAt(new java.util.Date(System.currentTimeMillis()))
                    .setExpiration(new java.util.Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                    .signWith(getPrivateKey(), io.jsonwebtoken.SignatureAlgorithm.RS256)
                    .compact();
        } catch (Exception e) {
            throw new RuntimeException("Error al generar el token JWT firmado con RSA", e);
        }
    }
}