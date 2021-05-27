package pl.asku.gateway.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AddRequestHeaderGatewayFilterFactory;
import org.springframework.cloud.gateway.support.GatewayToStringStyler;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import pl.asku.gateway.utils.JwtUtil;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Component
public class AddRequestHeaderCustomGatewayFilterFactory extends AddRequestHeaderGatewayFilterFactory {

    JwtUtil jwtUtil;

    @Autowired
    public AddRequestHeaderCustomGatewayFilterFactory(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(NameValueConfig config) {
        return new GatewayFilter() {
            public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
                String value = "";
                if(config.getName().equals("Username") && config.getValue().equals("username")
                    && exchange.getRequest().getHeaders().containsKey("Authorization")){
                    String authToken = Objects.requireNonNull(exchange.getRequest().getHeaders().get("Authorization")).get(0).substring(7);
                    value = jwtUtil.getUsernameFromToken(authToken);
                }
                String finalValue = value;
                ServerHttpRequest request = exchange.getRequest().mutate().headers((httpHeaders) -> {
                    httpHeaders.add(config.getName(), finalValue);
                }).build();
                return chain.filter(exchange.mutate().request(request).build());
            }

            public String toString() {
                return GatewayToStringStyler.filterToStringCreator(AddRequestHeaderCustomGatewayFilterFactory.this).append(config.getName(), config.getValue()).toString();
            }
        };
    }
}
