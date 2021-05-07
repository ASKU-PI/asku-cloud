package pl.asku.gateway.security.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import pl.asku.gateway.utils.JwtUtil;
import reactor.core.publisher.Mono;


@Component
public class AuthenticationManager implements ReactiveAuthenticationManager {

    @Autowired
    JwtUtil jwtUtil;
    
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String authToken = authentication.getCredentials().toString();

        try {
            String username = jwtUtil.getUsernameFromToken(authToken);
            if (!jwtUtil.check(authToken)) {
                return Mono.empty();
            }
            return Mono.just(new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    jwtUtil.getAuthoritiesFromToken(authToken)
            ));
        } catch (Exception e) {
            e.printStackTrace();
            return Mono.empty();
        }
    }
}
