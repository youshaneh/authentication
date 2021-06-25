package com.shane.authentication.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shane.authentication.config.SecurityConfig;
import com.shane.authentication.entity.auth.AuthRequest;
import com.shane.authentication.entity.auth.GoogleOAuthTokenResponse;
import com.shane.authentication.service.AuthService;
import lombok.SneakyThrows;
import okhttp3.*;
import okhttp3.ResponseBody;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping(value = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthController {
    @Autowired
    private SecurityConfig securityConfig;

    @Autowired
    private AuthService authService;

    @PostMapping
    public ResponseEntity<Map<String, String>> authenticate(@RequestBody AuthRequest request) {
        String token = authService.authenticate(request);
        Map<String, String> response = Collections.singletonMap("token", token);
        return ResponseEntity.ok(response);
    }

    @SneakyThrows
    @GetMapping("/google")
    public ResponseEntity<Void> googleOAuth(@RequestParam String code){
        String token = authService.googleOAuth(code);
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(
                securityConfig.getOauthResultPage() + "?token=" + token)).build();
    }
}