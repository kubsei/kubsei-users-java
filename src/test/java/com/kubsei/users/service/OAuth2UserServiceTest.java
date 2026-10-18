package com.kubsei.users.service;

import com.kubsei.users.model.AuthProvider;
import com.kubsei.users.model.User;
import com.kubsei.users.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuth2UserServiceTest {

    private static final String EMAIL = "ana@gmail.com";

    private final UserRepository users = mock(UserRepository.class);
    private final RefreshTokenService refreshTokens = mock(RefreshTokenService.class);
    private final OAuth2UserService service = new OAuth2UserService(users, refreshTokens);

    private static Map<String, Object> google(boolean emailVerified) {
        return Map.of("sub", "google-123", "email", EMAIL, "name", "Ana", "email_verified", emailVerified);
    }

    @Test
    void takesOverAPasswordAccountWithTheSameEmail() {
        User existing = User.builder().id("u1").email(EMAIL).password("hash-set-by-anyone")
                .provider(AuthProvider.LOCAL).build();
        when(users.findByProviderAndProviderId(AuthProvider.GOOGLE, "google-123")).thenReturn(Optional.empty());
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(existing));
        when(users.save(any(User.class))).thenAnswer(call -> call.getArgument(0));

        User result = service.resolveUser(AuthProvider.GOOGLE, google(true));

        assertThat(result).isSameAs(existing);
        assertThat(result.getProvider()).isEqualTo(AuthProvider.GOOGLE);
        assertThat(result.getProviderId()).isEqualTo("google-123");
        assertThat(result.getPassword()).isNull();
        verify(refreshTokens).revokeAllUserTokens("u1");
    }

    @Test
    void refusesToLinkWhenTheProviderHasNotVerifiedTheEmail() {
        User existing = User.builder().id("u1").email(EMAIL).password("hash").provider(AuthProvider.LOCAL).build();
        when(users.findByProviderAndProviderId(AuthProvider.GOOGLE, "google-123")).thenReturn(Optional.empty());
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> service.resolveUser(AuthProvider.GOOGLE, google(false)))
                .isInstanceOf(OAuth2AuthenticationException.class);
        assertThat(existing.getPassword()).isEqualTo("hash");
        verify(users, never()).save(any());
    }

    @Test
    void createsANewAccountWhenNothingMatches() {
        when(users.findByProviderAndProviderId(AuthProvider.GOOGLE, "google-123")).thenReturn(Optional.empty());
        when(users.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(users.save(any(User.class))).thenAnswer(call -> call.getArgument(0));

        User result = service.resolveUser(AuthProvider.GOOGLE, google(true));

        assertThat(result.getEmail()).isEqualTo(EMAIL);
        assertThat(result.getProviderId()).isEqualTo("google-123");
    }
}
