package com.example.Security.Config;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalAuthentication
@EnableMethodSecurity
public class SecurityConfig {

    private final JWTAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    //les listes n'est authentifies mais les autres doivent etres authentication
    @Bean
    public SecurityFilterChain SecurityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)// Disable CSRF protection

                // we delete this  .disable()
                .authorizeHttpRequests(authorizeHttp -> { // Configure authorization for HTTP requests using lambda expression
                            authorizeHttp.requestMatchers("/api/v1/auth/**").permitAll(); // Allow access to root URL
                            authorizeHttp.anyRequest().authenticated();// Require authentication for any other request

                        }
                )
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS))// Use stateless sessions (no server-side session storage)


                .authenticationProvider(authenticationProvider) // Set the authentication provider for custom authentication logic
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);// Add a filter before a specific filter class
        return http.build();  // Build and return the configured HttpSecurity object

    }


}


//  authorizeHttp.requestMatchers("/favicon.svg").permitAll();
//                            authorizeHttp.requestMatchers("/css/*").permitAll();
//                            authorizeHttp.requestMatchers("/error").permitAll();