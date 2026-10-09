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
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        AuthProvider provider = AuthProvider.valueOf(registrationId.toUpperCase());

        String providerId = extractProviderId(provider, attributes);
        String email = extractEmail(provider, attributes);
        String name = extractName(provider, attributes);
        String avatarUrl = extractAvatarUrl(provider, attributes);

        User user = userRepository.findByProviderAndProviderId(provider, providerId)
                .map(existingUser -> updateExistingUser(existingUser, name, avatarUrl))
                .orElseGet(() -> registerNewUser(provider, providerId, email, name, avatarUrl));

        return new UserPrincipal(user, attributes);
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
