package com.kubsei.users.api;

import com.kubsei.users.api.model.AuthResponse;
import com.kubsei.users.api.model.LoginRequest;
import com.kubsei.users.api.model.RefreshTokenRequest;
import com.kubsei.users.api.model.RegisterRequest;
import com.kubsei.users.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthApiDelegateImpl implements AuthApiDelegate {

    private final AuthService authService;
    private final HttpServletRequest request;

    @Override
    public ResponseEntity<AuthResponse> register(RegisterRequest body) {
        AuthService.Tokens tokens = authService.register(
                body.getEmail(), body.getPassword(), body.getName(), userAgent(), request.getRemoteAddr());
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(tokens));
    }

    @Override
    public ResponseEntity<AuthResponse> login(LoginRequest body) {
        AuthService.Tokens tokens = authService.login(
                body.getEmail(), body.getPassword(), userAgent(), request.getRemoteAddr());
        return ResponseEntity.ok(toResponse(tokens));
    }

    @Override
    public ResponseEntity<AuthResponse> refreshToken(RefreshTokenRequest body) {
        AuthService.Tokens tokens = authService.refreshToken(body.getRefreshToken(), userAgent(), request.getRemoteAddr());
        return ResponseEntity.ok(toResponse(tokens));
    }

    @Override
    public ResponseEntity<Void> logout(RefreshTokenRequest body) {
        authService.logout(body.getRefreshToken());
        return ResponseEntity.noContent().build();
    }

    @Override
    public ResponseEntity<Void> logoutAll() {
        authService.logoutAll(SecurityContextHolder.getContext().getAuthentication().getName());
        return ResponseEntity.noContent().build();
    }

    private String userAgent() {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "unknown";
    }

    private static AuthResponse toResponse(AuthService.Tokens tokens) {
        return new AuthResponse(tokens.accessToken(), tokens.refreshToken(), "Bearer", UserMapper.toApi(tokens.user()));
    }
}
