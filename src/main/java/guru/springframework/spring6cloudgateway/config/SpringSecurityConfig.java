package guru.springframework.spring6cloudgateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.zalando.logbook.HttpLogFormatter;
import org.zalando.logbook.Sink;
import org.zalando.logbook.json.JsonHttpLogFormatter;
import org.zalando.logbook.logstash.LogstashLogbackSink;

/**
 * @author john
 * @since 22/11/2024
 */
@Configuration
@EnableWebFluxSecurity
public class SpringSecurityConfig {

   /* @Bean
    @Order(1)
    public SecurityWebFilterChain actuatorSecurityWebFilterChain(ServerHttpSecurity http) {
        http.securityMatcher(EndpointRequest.toAnyEndpoint())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.anyExchange().permitAll())
                .build();
        return http.build();
    }*/

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity security) {
        return security.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(auth-> auth.pathMatchers("actuator/**").permitAll())
                .authorizeExchange(auth-> auth.pathMatchers("/oauth2/**", "/oauth2/token").permitAll())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.anyExchange().authenticated())
                .oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec.jwt(Customizer.withDefaults()))
                .build();
    }

    @Bean
    public Sink logbookLogStash() {
        HttpLogFormatter formatter = new JsonHttpLogFormatter();
        return new LogstashLogbackSink(formatter);
    }


}
