package com.kubsei.users.security;

import com.kubsei.users.config.OAuth2Properties;
import com.kubsei.users.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AuthService authService;
    private final OAuth2Properties oAuth2Properties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        if (response.isCommitted()) {
            log.debug("Response has already been committed");
            return;
        }

        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        AuthService.Tokens tokens = authService.issueTokens(
                principal.user(), request.getHeader("User-Agent"), request.getRemoteAddr());

        String targetUrl = UriComponentsBuilder.fromUriString(oAuth2Properties.defaultSuccessUrl())
                .queryParam("accessToken", tokens.accessToken())
                .queryParam("refreshToken", tokens.refreshToken())
                .build().toUriString();

        log.info("OAuth2 authentication successful for user: {}", principal.user().getEmail());

        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
