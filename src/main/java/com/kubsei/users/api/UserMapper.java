package com.kubsei.users.api;

import com.kubsei.users.api.model.AuthProvider;
import com.kubsei.users.api.model.Role;
import com.kubsei.users.model.User;

import java.util.stream.Collectors;

final class UserMapper {

    private UserMapper() {
    }

    static com.kubsei.users.api.model.User toApi(User user) {
        return new com.kubsei.users.api.model.User()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .avatarUrl(user.getAvatarUrl())
                .roles(user.getRoles().stream().map(role -> Role.valueOf(role.name())).collect(Collectors.toSet()))
                .provider(AuthProvider.valueOf(user.getProvider().name()))
                .emailVerified(user.isEmailVerified())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .lastLoginAt(user.getLastLoginAt());
    }
}
