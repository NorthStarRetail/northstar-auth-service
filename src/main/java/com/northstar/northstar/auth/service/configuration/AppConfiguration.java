package com.northstar.northstar.auth.service.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("auth")
public class AppConfiguration {

    private OauthClient oauth;
    private String msg;
    private String baseUrl;
    private String buildVersion;
    private JwtKey jwt;

    @Data
    public static class OauthClient {
        private String clientId;
        private String clientSecret;
        private RedirectUri redirectUri;
    }

    @Data
    public static class RedirectUri {
        private String login;
    }

    @Data
    public static class JwtKey {
        private String id;
    }
}
