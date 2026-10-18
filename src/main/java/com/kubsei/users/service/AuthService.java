package com.kubsei.users.service;

import com.kubsei.users.exception.AuthenticationException;
import com.kubsei.users.exception.InvalidRequestException;
import com.kubsei.users.exception.UserAlreadyExistsException;
import com.kubsei.users.model.AuthProvider;
import com.kubsei.users.model.RefreshToken;
import com.kubsei.users.model.Role;
import com.kubsei.users.model.User;
import com.kubsei.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    public record Tokens(String accessToken, String refreshToken, User user) {
    }

    static final int MAX_FAILED_LOGINS = 10;
    static final Duration LOCK_DURATION = Duration.ofMinutes(15);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public Tokens register(String email, String password, String name, String deviceInfo, String ipAddress) {
        if (tooLongForBcrypt(password)) {
            throw new InvalidRequestException("PASSWORD_TOO_LONG", "Password must be at most 72 bytes");
        }
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

        try {
            return issueTokens(userRepository.save(user), deviceInfo, ipAddress);
        } catch (DuplicateKeyException e) {
            // Two registrations with the same email at once: the unique index rejects the second
            throw new UserAlreadyExistsException("User with email " + email + " already exists");
        }
    }

    public Tokens login(String email, String password, String deviceInfo, String ipAddress) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("INVALID_CREDENTIALS", "Invalid email or password"));

        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new AuthenticationException("USE_PROVIDER", "Please use " + user.getProvider() + " to login");
        }

        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())) {
            throw new AuthenticationException("TOO_MANY_ATTEMPTS", "Too many failed attempts, try again later");
        }

        // No stored password can be longer than 72 bytes, and BCrypt throws on it instead of answering false
        if (tooLongForBcrypt(password) || !passwordEncoder.matches(password, user.getPassword())) {
            registerFailedLogin(user);
            throw new AuthenticationException("INVALID_CREDENTIALS", "Invalid email or password");
        }

        if (!user.isEnabled()) {
            throw new AuthenticationException("ACCOUNT_DISABLED", "Account is disabled");
        }

        user.setFailedLogins(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);

        return issueTokens(user, deviceInfo, ipAddress);
    }

    public Tokens refreshToken(String refreshTokenStr, String deviceInfo, String ipAddress) {
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(refreshTokenStr);

        User user = userRepository.findById(refreshToken.getUserId())
                .orElseThrow(() -> new AuthenticationException("SESSION_EXPIRED", "User not found"));

        refreshTokenService.revokeToken(refreshTokenStr);

        return issueTokens(user, deviceInfo, ipAddress);
    }

    public void logout(String refreshTokenStr) {
        refreshTokenService.revokeToken(refreshTokenStr);
    }

    public void logoutAll(String userId) {
        refreshTokenService.revokeAllUserTokens(userId);
    }

    // shortcut: read-modify-write, so parallel attempts can undercount by a few; fine against password guessing
    private void registerFailedLogin(User user) {
        int failed = user.getFailedLogins() + 1;
        if (failed >= MAX_FAILED_LOGINS) {
            user.setLockedUntil(Instant.now().plus(LOCK_DURATION));
            failed = 0;
        }
        user.setFailedLogins(failed);
        userRepository.save(user);
    }

    private static boolean tooLongForBcrypt(String password) {
        return password.getBytes(StandardCharsets.UTF_8).length > 72;
    }

    public Tokens issueTokens(User user, String deviceInfo, String ipAddress) {
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId(), deviceInfo, ipAddress);
        return new Tokens(jwtService.generateAccessToken(user), refreshToken.getToken(), user);
    }
}
