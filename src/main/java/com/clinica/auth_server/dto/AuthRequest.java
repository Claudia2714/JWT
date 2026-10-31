package com.clinica.auth_server.dto;

/**
 * DTO que recibe las credenciales del usuario y el token del widget Turnstile (CAPTCHA).
 */
public class AuthRequest {
    private String username;
    private String password;
    /** Token generado por el widget de Cloudflare Turnstile en el frontend */
    private String turnstileToken;

    public AuthRequest() {}

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getTurnstileToken() { return turnstileToken; }
    public void setTurnstileToken(String turnstileToken) { this.turnstileToken = turnstileToken; }
}