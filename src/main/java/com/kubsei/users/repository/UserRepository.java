package com.kubsei.users.repository;

import com.kubsei.users.model.AuthProvider;
import com.kubsei.users.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends MongoRepository<User, String> {

    Optional<User> findByEmail(String email);

    Optional<User> findByProviderAndProviderId(AuthProvider provider, String providerId);

    boolean existsByEmail(String email);

    Optional<User> findByEmailAndProvider(String email, AuthProvider provider);
}
