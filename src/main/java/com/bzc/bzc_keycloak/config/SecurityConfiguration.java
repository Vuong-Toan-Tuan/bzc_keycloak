package com.bzc.bzc_keycloak.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/public/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .defaultSuccessUrl("/home", true)
                        .failureUrl("/login?error=true"))
                .logout(logout -> logout
                        .logoutSuccessUrl("http://localhost:8080/realms/BZC/protocol/openid-connect/logout?redirect_uri=http://localhost:8080")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true));

        return http.build();
    }
}


//@Configuration
//public class SecurityConfiguration {
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/unauthenticated", "/oauth2/**", "/login/**").permitAll()
//                        .anyRequest().authenticated()
//                )
////                .oauth2Login(oauth2 -> oauth2
////                        .loginPage("/login") // Tùy chọn, nếu muốn trang login custom
//                .oauth2Login((oauth2 -> oauth2
//                        .defaultSuccessUrl("/", true))
//                )
//                .logout(logout -> logout
//                        .logoutSuccessUrl("http://192.168.100.2:1411/realms/BZC/protocol/openid-connect/logout?redirect_uri=http://localhost:8080/")
//                );
//
//        return http.build();
//    }
//}


