package com.kubsei.users.config;

import com.kubsei.users.api.model.Problem;
import com.kubsei.users.security.OAuth2AuthenticationSuccessHandler;
import com.kubsei.users.service.OAuth2UserService;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import tools.jackson.databind.json.JsonMapper;

import javax.crypto.SecretKey;
import java.util.Set;

@Configuration
public class SecurityConfig {

    /** Endpoints that must work with no token, or with an expired one (e.g. refresh). */
    private static final Set<String> PUBLIC_AUTH_PATHS = Set.of(
            "/api/auth/register", "/api/auth/login", "/api/auth/refresh", "/api/auth/logout");

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   OAuth2UserService oAuth2UserService,
                                                   OAuth2AuthenticationSuccessHandler successHandler,
                                                   OAuth2Properties oAuth2Properties,
                                                   AuthenticationEntryPoint problemEntryPoint) {
        DefaultBearerTokenResolver defaultResolver = new DefaultBearerTokenResolver();

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exception -> exception.authenticationEntryPoint(problemEntryPoint))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_AUTH_PATHS.toArray(String[]::new)).permitAll()
                        .requestMatchers("/oauth2/**", "/login/oauth2/**").permitAll()
                        .requestMatchers("/actuator/health/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenResolver(request -> PUBLIC_AUTH_PATHS.contains(
                                request.getRequestURI().substring(request.getContextPath().length()))
                                ? null : defaultResolver.resolve(request))
                        .authenticationEntryPoint(problemEntryPoint)
                        .jwt(Customizer.withDefaults()))
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
                        .successHandler(successHandler)
                        .failureUrl(oAuth2Properties.defaultFailureUrl()));

        return http.build();
    }

    @Bean
    public AuthenticationEntryPoint problemEntryPoint(JsonMapper jsonMapper) {
        return (request, response, ex) -> {
            response.setStatus(401);
            response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
            jsonMapper.writeValue(response.getOutputStream(),
                    new Problem().title("Unauthorized").status(401).detail(ex.getMessage())
                            .instance(request.getRequestURI()));
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /** Signs with the key from essential-security, which every other service verifies with. */
    @Bean
    public JwtEncoder jwtEncoder(SecretKey kubseiJwtSecretKey) {
        return new NimbusJwtEncoder(new ImmutableSecret<>(kubseiJwtSecretKey));
    }
}
