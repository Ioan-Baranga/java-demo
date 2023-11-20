package com.example.javademo.config;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.*;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Autowired
    private ApplicationContext context;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(customizeCors(context))
                .csrf(customizeCsrf(context))
                .authorizeHttpRequests(customizeAuthorizationHttpRequests(context))
                .sessionManagement(customizeSessionManagement(context))
                .exceptionHandling(customizeExceptionHandling(context));

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(BCryptPasswordEncoder bCryptPasswordEncoder) {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("user")
                .password(bCryptPasswordEncoder.encode("userPass"))
                .roles("USER")
                .build());
        manager.createUser(User.withUsername("admin")
                .password(bCryptPasswordEncoder.encode("adminPass"))
                .roles("USER", "ADMIN")
                .build());
        return manager;
    }

    private Customizer<CorsConfigurer<HttpSecurity>> customizeCors(ApplicationContext context) {
        return corsCustomizer -> {
            try {
                corsCustomizer
                        .configurationSource(corsConfigurationSource())
                        .disable(); // Disable CORS for simplicity; you can enable it if needed
            } catch (Exception e) {
                throw new RuntimeException("Error configuring CORS", e);
            }
        };
    }

    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("*");
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    private Customizer<CsrfConfigurer<HttpSecurity>> customizeCsrf(ApplicationContext context) {
        return csrfCustomizer -> {
            try {
                csrfCustomizer.csrfTokenRepository(csrfTokenRepository());
            } catch (Exception e) {
                throw new RuntimeException("Error configuring CSRF", e);
            }
        };
    }

    private CsrfTokenRepository csrfTokenRepository() {
        return CookieCsrfTokenRepository.withHttpOnlyFalse();
    }

    private Customizer<SessionManagementConfigurer<HttpSecurity>> customizeSessionManagement(ApplicationContext context) {
        return sessionManagementCustomizer -> {
            try {
                sessionManagementCustomizer
                        .sessionFixation().none() // Choose the appropriate session fixation strategy
                        .invalidSessionUrl("/invalidSession.html") // Specify the URL to redirect to on an invalid session
                        .maximumSessions(1) // Configure maximum sessions
                        .maxSessionsPreventsLogin(false) // Allow or prevent login when the maximum sessions are reached
                        .expiredUrl("/sessionExpired.html"); // Specify the URL to redirect to when a session expires
            } catch (Exception e) {
                throw new RuntimeException("Error configuring session management", e);
            }
        };
    }

    private Customizer<ExceptionHandlingConfigurer<HttpSecurity>> customizeExceptionHandling(ApplicationContext context) {
        return exceptionHandlingCustomizer -> {
            try {
                exceptionHandlingCustomizer
                        .authenticationEntryPoint((request, response, ex) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage()));
            } catch (Exception e) {
                throw new RuntimeException("Error configuring exception handling", e);
            }
        };
    }

    private Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry> customizeAuthorizationHttpRequests(ApplicationContext context) {
        return authorizationHttpRequestsCustomizer -> {
            try {
                authorizationHttpRequestsCustomizer
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated();
            } catch (Exception e) {
                throw new RuntimeException("Error configuring authorization for HTTP requests", e);
            }
        };
    }

}
