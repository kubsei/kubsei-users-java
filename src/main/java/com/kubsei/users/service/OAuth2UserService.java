package com.kubsei.users.service;

import com.kubsei.users.model.AuthProvider;
import com.kubsei.users.model.Role;
import com.kubsei.users.model.User;
import com.kubsei.users.repository.UserRepository;
import com.kubsei.users.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        Map<String, Object> attributes = oAuth2User.getAttributes();
        AuthProvider provider = AuthProvider.valueOf(registrationId.toUpperCase());

        return new UserPrincipal(resolveUser(provider, attributes), attributes);
    }

    /** The account for this provider login: the linked one, the one with the same email, or a new one. */
    User resolveUser(AuthProvider provider, Map<String, Object> attributes) {
        String providerId = extractProviderId(provider, attributes);
        String email = extractEmail(provider, attributes);
        String name = extractName(provider, attributes);
        String avatarUrl = extractAvatarUrl(provider, attributes);

        return userRepository.findByProviderAndProviderId(provider, providerId)
                .map(existingUser -> updateExistingUser(existingUser, name, avatarUrl))
                .orElseGet(() -> userRepository.findByEmail(email)
                        .map(existingUser -> linkProvider(existingUser, provider, providerId, attributes, name, avatarUrl))
                        .orElseGet(() -> registerNewUser(provider, providerId, email, name, avatarUrl)));
    }

    /**
     * Same email, registered with a password. The provider proves the email belongs to whoever is logging in,
     * while the password may have been set by someone else (sign-up does not verify emails): the provider takes
     * over, the password is dropped and every open session is closed.
     */
    private User linkProvider(User user, AuthProvider provider, String providerId,
                              Map<String, Object> attributes, String name, String avatarUrl) {
        if (!Boolean.TRUE.equals(attributes.get("email_verified"))) {
            throw new OAuth2AuthenticationException(new OAuth2Error("email_not_verified"),
                    "The provider has not verified " + user.getEmail());
        }
        user.setProvider(provider);
        user.setProviderId(providerId);
        user.setPassword(null);
        user.setEmailVerified(true);
        user.setFailedLogins(0);
        user.setLockedUntil(null);
        refreshTokenService.revokeAllUserTokens(user.getId());
        return updateExistingUser(user, name, avatarUrl);
    }

    private String extractProviderId(AuthProvider provider, Map<String, Object> attributes) {
        return switch (provider) {
            case GOOGLE -> (String) attributes.get("sub");
            default -> throw new OAuth2AuthenticationException("Unsupported provider");
        };
    }

    private String extractEmail(AuthProvider provider, Map<String, Object> attributes) {
        return switch (provider) {
            case GOOGLE -> (String) attributes.get("email");
            default -> throw new OAuth2AuthenticationException("Unsupported provider");
        };
    }

    private String extractName(AuthProvider provider, Map<String, Object> attributes) {
        return switch (provider) {
            case GOOGLE -> (String) attributes.get("name");
            default -> null;
        };
    }

    private String extractAvatarUrl(AuthProvider provider, Map<String, Object> attributes) {
        return switch (provider) {
            case GOOGLE -> (String) attributes.get("picture");
            default -> null;
        };
    }

    private User updateExistingUser(User user, String name, String avatarUrl) {
        user.setName(name);
        user.setAvatarUrl(avatarUrl);
        user.setLastLoginAt(Instant.now());
        return userRepository.save(user);
    }

    private User registerNewUser(AuthProvider provider, String providerId,
                                  String email, String name, String avatarUrl) {
        User user = User.builder()
                .email(email)
                .name(name)
                .avatarUrl(avatarUrl)
                .provider(provider)
                .providerId(providerId)
                .emailVerified(true)
                .enabled(true)
                .roles(Set.of(Role.EDITOR))
                .build();

        return userRepository.save(user);
    }
}
