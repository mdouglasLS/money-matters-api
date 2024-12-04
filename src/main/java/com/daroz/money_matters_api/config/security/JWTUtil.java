package com.daroz.money_matters_api.config.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JWTUtil {

    @Value("${spring.security.accessToken.secret}")
    public String accessTokenSecret;

    @Value("${spring.security.refreshToken.secret}")
    public String refreshTokenSecret;

    @Value("${security.jwt.duration.access}")
    private Long accessTokenDuration;

    @Value("${security.jwt.duration.refresh}")
    private Long refreshTokenDuration;

    public String generateAccessToken(CustomUser user, HttpServletRequest request) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withClaim("id", user.getId())
                .withClaim("name", user.getName())
                .withExpiresAt(Date.from(Instant.now().plusSeconds(accessTokenDuration)))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList())
                )
                .sign(Algorithm.HMAC512(accessTokenSecret));
    }

    public String generateRefreshToken(CustomUser user, HttpServletRequest request) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withClaim("id", user.getId())
                .withClaim("name", user.getName())
                .withIssuer(request.getRequestURL().toString())
                .withExpiresAt(Date.from(Instant.now().plusSeconds(refreshTokenDuration)))
                .sign(Algorithm.HMAC512(refreshTokenSecret));
    }

    public DecodedJWT validateToken(String token, boolean isRefreshToken) throws JWTVerificationException {
        String secret = isRefreshToken ? refreshTokenSecret : accessTokenSecret;
        Algorithm algorithm = Algorithm.HMAC512(secret);
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(token);
    }

}
