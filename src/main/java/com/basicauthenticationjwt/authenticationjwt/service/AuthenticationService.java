package com.basicauthenticationjwt.authenticationjwt.service;

import com.basicauthenticationjwt.authenticationjwt.model.User;
import com.basicauthenticationjwt.authenticationjwt.repository.UserRepository;
import com.basicauthenticationjwt.authenticationjwt.utils.AuthenticationRequest;
import com.basicauthenticationjwt.authenticationjwt.utils.AuthenticationResponse;
import com.basicauthenticationjwt.authenticationjwt.utils.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final Handler handler;

    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();
        userRepository.save(user);
        var token = handler.generateToken(user);
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        var token = handler.generateToken(user);
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }

}
