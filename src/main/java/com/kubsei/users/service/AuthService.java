package com.kubsei.users.service;

import com.kubsei.users.exception.AuthenticationException;
import com.kubsei.users.exception.UserAlreadyExistsException;
import com.kubsei.users.model.AuthProvider;
import com.kubsei.users.model.RefreshToken;
import com.kubsei.users.model.Role;
import com.kubsei.users.model.User;
import com.kubsei.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    public record Tokens(String accessToken, String refreshToken, User user) {
    }

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public Tokens register(String email, String password, String name, String deviceInfo, String ipAddress) {
        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException("User with email " + email + " already exists");
        }

        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .name(name)
                .roles(Set.of(Role.EDITOR))
                .provider(AuthProvider.LOCAL)
                .emailVerified(false)
                .enabled(true)
                .build();

        return issueTokens(userRepository.save(user), deviceInfo, ipAddress);
    }

    public Tokens login(String email, String password, String deviceInfo, String ipAddress) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("Invalid email or password"));

        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new AuthenticationException("Please use " + user.getProvider() + " to login");
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new AuthenticationException("Invalid email or password");
        }

        if (!user.isEnabled()) {
            throw new AuthenticationException("Account is disabled");
        }

        user.setLastLoginAt(Instant.now());
        userRepository.save(user);

        return issueTokens(user, deviceInfo, ipAddress);
    }

    public Tokens refreshToken(String refreshTokenStr, String deviceInfo, String ipAddress) {
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(refreshTokenStr);

        User user = userRepository.findById(refreshToken.getUserId())
                .orElseThrow(() -> new AuthenticationException("User not found"));

        refreshTokenService.revokeToken(refreshTokenStr);

        return issueTokens(user, deviceInfo, ipAddress);
    }

    public void logout(String refreshTokenStr) {
        refreshTokenService.revokeToken(refreshTokenStr);
    }

    public void logoutAll(String userId) {
        refreshTokenService.revokeAllUserTokens(userId);
    }

    public Tokens issueTokens(User user, String deviceInfo, String ipAddress) {
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId(), deviceInfo, ipAddress);
        return new Tokens(jwtService.generateAccessToken(user), refreshToken.getToken(), user);
    }
}
