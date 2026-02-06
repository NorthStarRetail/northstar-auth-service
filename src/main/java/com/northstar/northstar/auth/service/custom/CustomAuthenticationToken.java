package com.northstar.northstar.auth.service.custom;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.io.Serial;
import java.util.Map;
import java.util.Set;

@Getter
public class CustomAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String username;
    private final String password;
    private final String clientId;
    private final Set<String> scopes;
    private final Map<String, Object> additionalParameters;

    public CustomAuthenticationToken(String username, String password, Authentication clientPrincipal,
                                     Set<String> scopes, Map<String, Object> additionalParameters) {
        super(CustomAuthenticationConverter.PASSWORD_GRANT_TYPE, clientPrincipal, additionalParameters);
        this.password = password;
        this.username = username;
        this.clientId = clientPrincipal.getName();
        this.scopes = scopes;
        this.additionalParameters = additionalParameters;
    }
}
