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

public class JWTValidateFilter extends BasicAuthenticationFilter {

    public final String accessTokenSecret;

    public static final String BEARER_HEADER = "Bearer ";

    public JWTValidateFilter(AuthenticationManager authenticationManager, String accessTokenSecret) {
        super(authenticationManager);
        this.accessTokenSecret = accessTokenSecret;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws IOException, ServletException {

        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (!Objects.isNull(authorizationHeader) && authorizationHeader.startsWith(BEARER_HEADER)) {
            try {
                String token = authorizationHeader.substring(BEARER_HEADER.length());
                Algorithm algorithm = Algorithm.HMAC512(accessTokenSecret);
                JWTVerifier build = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = build.verify(token);
                String username = decodedJWT.getSubject();
                String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                Arrays.stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                chain.doFilter(request, response);
            } catch (Exception e) {
                response.sendError(HttpStatus.BAD_REQUEST.value(), e.getMessage());
            }
        } else chain.doFilter(request, response);
    }

}
