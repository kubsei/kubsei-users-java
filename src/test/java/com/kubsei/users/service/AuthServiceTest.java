package com.kubsei.users.service;

import com.kubsei.users.exception.AuthenticationException;
import com.kubsei.users.exception.InvalidRequestException;
import com.kubsei.users.model.AuthProvider;
import com.kubsei.users.model.RefreshToken;
import com.kubsei.users.model.User;
import com.kubsei.users.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private static final String EMAIL = "ana@example.com";
    private static final String TOO_LONG = "ñ".repeat(40); // 40 characters, 80 bytes

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    private final UserRepository users = mock(UserRepository.class);
    private final RefreshTokenService refreshTokens = mock(RefreshTokenService.class);
    private final AuthService authService = new AuthService(users, encoder, mock(JwtService.class), refreshTokens);
    private User user;

    @BeforeEach
    void setUp() {
        user = User.builder().id("u1").email(EMAIL).password(encoder.encode("correct-password"))
                .provider(AuthProvider.LOCAL).build();
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(users.save(any(User.class))).thenAnswer(call -> call.getArgument(0));
        when(refreshTokens.createRefreshToken(any(), any(), any()))
                .thenReturn(RefreshToken.builder().token("refresh").build());
    }

    @Test
    void locksTheAccountAfterTooManyWrongPasswords() {
        for (int i = 0; i < AuthService.MAX_FAILED_LOGINS; i++) {
            assertCode(() -> authService.login(EMAIL, "wrong", "ua", "ip"), "INVALID_CREDENTIALS");
        }

        // Even the right password is refused while locked
        assertCode(() -> authService.login(EMAIL, "correct-password", "ua", "ip"), "TOO_MANY_ATTEMPTS");
    }

    @Test
    void aSuccessfulLoginResetsTheCounter() {
        for (int i = 0; i < AuthService.MAX_FAILED_LOGINS - 1; i++) {
            assertCode(() -> authService.login(EMAIL, "wrong", "ua", "ip"), "INVALID_CREDENTIALS");
        }

        assertThat(authService.login(EMAIL, "correct-password", "ua", "ip").user()).isSameAs(user);
        assertThat(user.getFailedLogins()).isZero();
        assertThat(user.getLockedUntil()).isNull();
    }

    @Test
    void passwordsLongerThan72BytesGetACodeInsteadOfABcryptError() {
        assertThatThrownBy(() -> authService.register("new@example.com", TOO_LONG, "Ana", "ua", "ip"))
                .isInstanceOf(InvalidRequestException.class)
                .extracting(ex -> ((InvalidRequestException) ex).getCode()).isEqualTo("PASSWORD_TOO_LONG");

        assertCode(() -> authService.login(EMAIL, TOO_LONG, "ua", "ip"), "INVALID_CREDENTIALS");
    }

    private static void assertCode(Runnable call, String code) {
        assertThatThrownBy(call::run)
                .isInstanceOf(AuthenticationException.class)
                .extracting(ex -> ((AuthenticationException) ex).getCode()).isEqualTo(code);
    }
}
