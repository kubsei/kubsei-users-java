package com.kubsei.users.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/** Lifetimes of the tokens this service issues. Secret and issuer: kubsei.security.jwt (essential-security). */
@ConfigurationProperties(prefix = "app.jwt")
public record TokenProperties(Duration accessTokenExpiration, Duration refreshTokenExpiration) {
}
