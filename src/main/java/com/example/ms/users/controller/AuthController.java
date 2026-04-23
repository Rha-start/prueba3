package com.example.ms.users.controller;


import com.example.ms.users.model.User;
import com.example.ms.users.security.jwt.JwtService;
import com.example.ms.users.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")


public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserService userService;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService, UserService userService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userService = userService;
    }
@PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        try {
            String username = body.get("username");
            String password = body.get("password");
            String role = body.getOrDefault("role", "USER");


            if (username == null || password == null || username.isBlank() || password.isBlank()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Username y password son requeridos"));
            }

            // Validar rol
            if (!role.equals("USER") && !role.equals("ADMIN")) {
                role = "USER";
            }

            userService.register(username, password, role);
            return ResponseEntity.ok(Map.of(
                    "message", "Usuario registrado correctamente",
                    "role", role
            ));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("error", "El usuario ya existe"));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        try {
            String username = body.get("username");
            String password = body.get("password");

            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));

            if (auth.isAuthenticated()) {
                // Obtener rol del usuario
                User user = userService.findByUsername(username)
                        .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

                String token = jwtService.generateToken(username, user.getRole());

                return ResponseEntity.ok(Map.of(
                        "token", token,
                        "username", username,
                        "role", user.getRole() // Devolver rol
                ));
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Credenciales inválidas"));

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Usuario o contraseña incorrectos"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error al procesar la solicitud"));
        }
    }

    @GetMapping("/validate")
    public ResponseEntity<?> validateToken() {
        return ResponseEntity.ok(Map.of("valid", true));

    }
}