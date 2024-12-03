package com.daroz.money_matters_api.config.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.daroz.money_matters_api.data.dtos.auth.TokenResponseDTO;
import com.daroz.money_matters_api.data.models.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.stream.Collectors;

public class JWTAuthenticatorFilter extends UsernamePasswordAuthenticationFilter {

    public final String accessTokenSecret;

    public final String refreshTokenSecret;

    private final Long accessTokenDuration;

    private final Long refreshTokenDuration;

    @Override
    public void afterPropertiesSet() {
        super.afterPropertiesSet();
    }

    private final AuthenticationManager authenticationManager;

    public JWTAuthenticatorFilter(AuthenticationManager authenticationManager, String accessTokenSecret, String refreshTokenSecret, Long accessTokenDuration, Long refreshTokenDuration) {
        this.authenticationManager = authenticationManager;
        this.accessTokenSecret = accessTokenSecret;
        this.refreshTokenSecret = refreshTokenSecret;
        this.accessTokenDuration = accessTokenDuration;
        this.refreshTokenDuration = refreshTokenDuration;

    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws AuthenticationException {
        try {

            User user = new ObjectMapper().readValue(request.getInputStream(), User.class);

            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    user.getUsername(),
                    user.getPassword(),
                    user.getAuthorities()
            ));

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult
    ) throws IOException {

        CustomUser user = (CustomUser) authResult.getPrincipal();

        String accessToken = JWT.create()
                .withSubject(user.getUsername())
                .withClaim("name", user.getName())
                .withClaim("id", user.getId())
                .withExpiresAt(Date.from(Instant.now().plusSeconds(accessTokenDuration)))
                .withIssuer(request.getRequestURL().toString())
                .withClaim(
                        "roles",
                        user.getAuthorities()
                                .stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())
                )
                .sign(Algorithm.HMAC512(accessTokenSecret));

        String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withClaim("name", user.getName())
                .withClaim("id", user.getId())
                .withExpiresAt(Date.from(Instant.now().plusSeconds(refreshTokenDuration)))
                .withIssuer(request.getRequestURL().toString())
                .withClaim(
                        "roles",
                        user.getAuthorities()
                                .stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())
                )
                .sign(Algorithm.HMAC512(refreshTokenSecret));

        TokenResponseDTO responseDTO = new TokenResponseDTO(accessToken, refreshToken, Instant.now().plusSeconds(accessTokenDuration).toString());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        new ObjectMapper().writeValue(response.getOutputStream(), responseDTO);
    }
}
