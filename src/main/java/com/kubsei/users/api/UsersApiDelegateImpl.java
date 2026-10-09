package com.kubsei.users.api;

import com.kubsei.users.api.model.User;
import com.kubsei.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UsersApiDelegateImpl implements UsersApiDelegate {

    private final UserRepository userRepository;

    @Override
    public ResponseEntity<User> getCurrentUser() {
        String userId = SecurityContextHolder.getContext().getAuthentication().getName();
        return ResponseEntity.of(userRepository.findById(userId).map(UserMapper::toApi));
    }
}
