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

    private final Map<HttpMethod, String[]> ANONYMOUS_ENDPOINTS = Map.of(
            HttpMethod.GET, new String[]{
                    "/auth/v2/api-docs",
                    "/account/v2/api-docs",
                    "/magazine/v2/api-docs",
                    "/swagger-ui/**",
                    "/v2/api-docs",
                    "/swagger-resources/**",
                    "/swagger-ui.html",
                    "/webjars/**"
            }
    );

    private final Map<HttpMethod, String[]> OPEN_ENDPOINTS = Map.of(
            HttpMethod.POST, new String[]{
                    "/auth/api/login",
                    "/auth/api/register"
            },
            HttpMethod.GET, new String[]{
                    "/account/api/hello",
                    "/account/api/user",

                    "/magazine/api/hello",
                    "/magazine/api/search",
                    "/magazine/api/details/**"
            }
    );

    private final Map<HttpMethod, String[]> USER_ENDPOINTS = Map.of(
            HttpMethod.GET, new String[]{
                    "/auth/api/user"
            },
            HttpMethod.POST, new String[]{
                    "/magazine/api/add"
            }
    );

    private final Map<HttpMethod, String[]> MODERATOR_ENDPOINTS = Map.of(
            HttpMethod.GET, new String[]{
                    "/auth/api/user/**"
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
                .pathMatchers(HttpMethod.GET, ANONYMOUS_ENDPOINTS.get(HttpMethod.GET)).permitAll()
                .and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.POST, OPEN_ENDPOINTS.get(HttpMethod.POST)).permitAll()
                .pathMatchers(HttpMethod.GET, OPEN_ENDPOINTS.get(HttpMethod.GET)).permitAll()
                .and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.GET, USER_ENDPOINTS.get(HttpMethod.GET)).hasRole("USER")
                .pathMatchers(HttpMethod.POST, USER_ENDPOINTS.get(HttpMethod.POST)).hasRole("USER")
                .and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.GET, MODERATOR_ENDPOINTS.get(HttpMethod.GET)).hasRole("MODERATOR")
                .anyExchange().denyAll()
                .and()
                .build();
    }
}
