package com.northstar.northstar.auth.service.configuration;

import com.northstar.northstar.auth.service.custom.CustomAuthenticationConverter;
import com.northstar.northstar.auth.service.custom.CustomAuthenticationProvider;
import com.northstar.northstar.auth.service.repository.UserRepository;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {

    private static final String[] WHITELIST = {
            "/login", "/login/**", "/logout", "/oauth2/**", "/error",
            "/v1/guests/**", "/v1/roles/**", "/v1/roles",
            "/v1/auth/v3/api-docs", "/v3/api-docs", "/v3/api-docs/**",
            "/configuration/**", "/swagger-ui/**", "/swagger-resources/**",
            "/swagger-ui.html", "/api-docs/**", "/webjars/**"
    };

    private final AppConfiguration appConfiguration;
    private final PasswordEncoder passwordEncoder;

    public SecurityConfiguration(AppConfiguration appConfiguration, @Lazy PasswordEncoder passwordEncoder) {
        this.appConfiguration = appConfiguration;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            UserDetailsService userDetailsService,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint ->
                tokenEndpoint
                        .accessTokenRequestConverter(new CustomAuthenticationConverter())
                        .authenticationProvider(new CustomAuthenticationProvider(
                                userDetailsService, passwordEncoder, authorizationService, tokenGenerator)));

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http.securityMatcher(endpointsMatcher)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer);

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers(WHITELIST).permitAll()
                                .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }

    @Bean
    public JdbcRegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        JdbcRegisteredClientRepository repo = new JdbcRegisteredClientRepository(jdbcTemplate);
        if (repo.findByClientId(appConfiguration.getOauth().getClientId()) == null) {
            String redirectUri = appConfiguration.getOauth().getRedirectUri() != null
                    && appConfiguration.getOauth().getRedirectUri().getLogin() != null
                    ? appConfiguration.getOauth().getRedirectUri().getLogin()
                    : "http://localhost:8181/login/oauth2/code/northstar";
            RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(appConfiguration.getOauth().getClientId())
                    .clientSecret(passwordEncoder.encode(appConfiguration.getOauth().getClientSecret()))
                    .clientName("NorthStar")
                    .redirectUri(redirectUri)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(new AuthorizationGrantType("password"))
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofDays(1)).build())
                    .build();
            repo.save(client);
        }
        return repo;
    }

    @Bean
    JdbcOAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    OAuth2TokenGenerator<?> tokenGenerator(
            JWKSource<SecurityContext> jwkSource,
            OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(oAuth2TokenCustomizer);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        return new DelegatingPasswordEncoder("bcrypt", encoders);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer(UserRepository userRepository) {
        return context -> {
            if (AuthorizationGrantType.PASSWORD.equals(context.getAuthorizationGrantType())
                    && OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().claim("authorities",
                        context.getPrincipal().getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority).toList());
                userRepository.findUserByUsername(context.getPrincipal().getName())
                        .ifPresent(user -> context.getClaims().claims(claims -> {
                            claims.put("username", user.getUsername());
                            claims.put("name", user.getName());
                            claims.put("id", user.getId());
                            claims.put("uid", user.getUid());
                            claims.put("firstname", user.getFirstname());
                            claims.put("lastname", user.getLastname());
                            claims.put("roles", user.getRoles().stream()
                                    .map(GrantedAuthority::getAuthority).toList());
                        }));
            }
        };
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        String issuer = appConfiguration.getBaseUrl() != null ? appConfiguration.getBaseUrl() + "/api/auth" : "http://localhost:8181/api/auth";
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().requestMatchers("/webjars/**", "/v1/guests/**", "/v1/roles/**", "/v1/roles");
    }
}
