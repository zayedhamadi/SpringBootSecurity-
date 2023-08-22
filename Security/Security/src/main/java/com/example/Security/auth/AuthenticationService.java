package com.example.Security.auth;


import com.example.Security.Repository.UserRepository;

import com.example.Security.User.Role;
import com.example.Security.User.User;
import com.example.Security.Service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor

public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder PasswordEncoder;
    private final JwtService JwtService;
    private final AuthenticationManager AuthenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .lastname(request.getLastname())
                .firstname(request.getFirstname())
                .email(request.getEmail())
                .password(PasswordEncoder.encode(request.getPassword()))
                .role(Role.User)
                .build();
        repository.save(user);
        var jwToken = JwtService.generateToken(user);
        return AuthenticationResponse
                .builder()
                .token(jwToken)
                .build();

    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        AuthenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user =repository.findByEmail(request.getEmail()).orElseThrow();
        var jwToken = JwtService.generateToken(user);
        return AuthenticationResponse
                .builder()
                .token(jwToken)
                .build();
    }
}
