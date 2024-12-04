package com.daroz.money_matters_api.config.security;

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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.time.Instant;

public class JWTAuthenticatorFilter extends UsernamePasswordAuthenticationFilter {

    private final JWTUtil jwtUtil;

    private final Long accessTokenDuration;

    @Override
    public void afterPropertiesSet() {
        super.afterPropertiesSet();
    }

    private final AuthenticationManager authenticationManager;

    public JWTAuthenticatorFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, Long accessTokenDuration) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.accessTokenDuration = accessTokenDuration;
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

        String accessToken = jwtUtil.generateAccessToken(user, request);
        String refreshToken = jwtUtil.generateRefreshToken(user, request);

        TokenResponseDTO responseDTO = new TokenResponseDTO(accessToken, refreshToken, Instant.now().plusSeconds(accessTokenDuration).toString());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        new ObjectMapper().writeValue(response.getOutputStream(), responseDTO);
    }
}
