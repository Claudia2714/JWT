package com.clinica.auth_server.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

@Service
public class JwtValidationService {

    private PublicKey getPublicKey() throws Exception {
        InputStream inputStream = new ClassPathResource("public.pem").getInputStream();
        String keyString = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);

        String publicKeyPEM = keyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(decoded));
    }

    public Claims validateToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getPublicKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            return null;
        }
    }

    public String validateTokenAndGetUsername(String token) {
        Claims claims = validateToken(token);
        return claims != null ? claims.getSubject() : null;
    }

    @SuppressWarnings("unchecked")
    public List<String> getRoles(String token) {
        Claims claims = validateToken(token);
        if (claims != null && claims.get("roles") instanceof List) {
            return (List<String>) claims.get("roles");
        }
        return List.of();
    }
}
