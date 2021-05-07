package pl.asku.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import pl.asku.gateway.security.auth.AuthenticationManager;
import pl.asku.gateway.security.auth.SecurityContextRepository;
import reactor.core.publisher.Mono;

import java.util.Map;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

    private final Map<HttpMethod, String[]> OPEN_ENDPOINTS = Map.of(
            HttpMethod.POST, new String[]{
                    "/auth/login",
                    "/auth/register"
            }
    );

    private final Map<HttpMethod, String[]> USER_ENDPOINTS = Map.of(
            HttpMethod.GET, new String[]{
                    "/auth/user"
            }
    );

    private final Map<HttpMethod, String[]> MODERATOR_ENDPOINTS = Map.of(
            HttpMethod.GET, new String[]{
                    "/auth/user/**"
            }
    );

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    private SecurityContextRepository securityContextRepository;

    @Bean
    public SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
        return http
                .exceptionHandling()
                .authenticationEntryPoint((swe, e) -> Mono.fromRunnable(() ->
                        swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)))
                .accessDeniedHandler((swe, e) -> Mono.fromRunnable(() ->
                        swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN)))
                .and()
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange()
                .and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.POST, OPEN_ENDPOINTS.get(HttpMethod.POST)).permitAll()
                .pathMatchers(HttpMethod.GET, USER_ENDPOINTS.get(HttpMethod.GET)).hasRole("USER")
                .and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.GET, MODERATOR_ENDPOINTS.get(HttpMethod.GET)).hasRole("MODERATOR")
                .anyExchange().denyAll()
                .and()
                .build();
    }
}