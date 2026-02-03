package com.foodapp.controller;

import com.foodapp.dto.LoginRequest;
import com.foodapp.model.User;
import com.foodapp.repository.UserRepository;
import com.foodapp.security.JwtUtil;
import com.foodapp.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(
        origins = {
                "http://localhost:5173",
                "https://foodaplicationfrontend.onrender.com"
        },
        allowedHeaders = "*",
        methods = {
                RequestMethod.GET,
                RequestMethod.POST,
                RequestMethod.PUT,
                RequestMethod.DELETE,
                RequestMethod.OPTIONS
        },
        allowCredentials = "true"
)
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    // REGISTER USER
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        user.setRole("USER");
        User saved = userService.registerUser(user);
        saved.setPassword(null);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    // REGISTER ADMIN
    @PostMapping("/register-admin")
    public ResponseEntity<?> registerAdmin(@RequestBody User user) {
        user.setRole("ADMIN");
        User saved = userService.registerUser(user);
        saved.setPassword(null);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    // LOGIN
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {

        if (request.getEmail() == null || request.getEmail().trim().isEmpty()
                || request.getPassword() == null || request.getPassword().trim().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Email and password are required"));
        }

        User user = userRepository.findByEmail(request.getEmail().trim())
                .orElse(null);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not found"));
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid password"));
        }

        String token = jwtUtil.generateToken(user.getEmail());

        Map<String, String> response = new HashMap<>();
        response.put("token", token);
        response.put("role", user.getRole());
        response.put("email", user.getEmail());

        return ResponseEntity.ok(response);
    }
}
