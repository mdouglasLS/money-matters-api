package com.daroz.money_matters_api.config.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;
import java.util.stream.Collectors;

public class JWTValidateFilter extends BasicAuthenticationFilter {

    private final JWTUtil jwtUtil;

    public static final String BEARER_HEADER = "Bearer ";

    public JWTValidateFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        super(authenticationManager);
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws IOException, ServletException {

        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (Objects.nonNull(authorizationHeader) && authorizationHeader.startsWith(BEARER_HEADER)) {
            try {

                String token = authorizationHeader.substring(BEARER_HEADER.length());
                DecodedJWT decodedJWT = jwtUtil.validateToken(token, false);
                UsernamePasswordAuthenticationToken authentication = getAuthentication(decodedJWT);
                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (Exception e) {
                response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid token: " + e.getMessage());
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(DecodedJWT decodedJWT) {
        String username = decodedJWT.getSubject();
        String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

        Collection<SimpleGrantedAuthority> authorities = Arrays.stream(roles)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }

}
