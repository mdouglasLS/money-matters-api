package com.daroz.money_matters_api.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.daroz.money_matters_api.data.dtos.RoleDTO;
import com.daroz.money_matters_api.data.dtos.UserDTO;
import com.daroz.money_matters_api.data.dtos.UserRegisterDTO;
import com.daroz.money_matters_api.data.dtos.auth.EmailDTO;
import com.daroz.money_matters_api.data.dtos.auth.ResetPasswordDTO;
import com.daroz.money_matters_api.data.dtos.auth.TokenRefreshTokenDTO;
import com.daroz.money_matters_api.data.dtos.auth.TokenResponseDTO;
import com.daroz.money_matters_api.data.enums.RolesENUM;
import com.daroz.money_matters_api.data.models.PasswordRecoverToken;
import com.daroz.money_matters_api.data.models.Role;
import com.daroz.money_matters_api.data.models.User;
import com.daroz.money_matters_api.repositories.PasswordRecoverTokenRepository;
import com.daroz.money_matters_api.repositories.RoleRepository;
import com.daroz.money_matters_api.repositories.UserRepository;
import com.daroz.money_matters_api.services.exceptions.ForbiddenException;
import com.daroz.money_matters_api.services.exceptions.ResourceNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Transactional(readOnly = true)
@Service
public class AuthService {

    @Autowired
    private UserRepository repository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordRecoverTokenRepository passwordRecoverTokenRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private ModelMapper modelMapper;

    @Value("${spring.security.accessToken.secret}")
    public String accessTokenSecret;

    @Value("${security.jwt.duration.access}")
    private Long accessTokenDuration;

    @Value("${security.password.recover.token.minutes}")
    private Long tokenExpirationTime;

    @Value("${security.password.recover.token.uri}")
    private String recoverUri;

    public void createUser(UserRegisterDTO dto) {
        String authenticated = authenticated().getUsername();
        UUID uuid = UUID.randomUUID();
        log.info("createUser: {}\nRequested by: {}", uuid, authenticated);

        log.info("Checking if email already exists: {}\nEmail: {}", uuid, dto.email());
        if (!repository.checkEmailAvailable(dto.email())) {
            log.error("Email already exists: {}", uuid);
            throw new IllegalArgumentException("Este email já está em uso.");
        }

        log.info("Checking if username already exists: {}\nUsername: {}", uuid, dto.username());
        if (!repository.checkUsernameAvailable(dto.username())) {
            log.error("Username already exists: {}", uuid);
            throw new IllegalArgumentException("Este username já está em uso.");
        }

        List<Role> roles = roleRepository.findAllById(dto.roles().stream().map(RoleDTO::id).toList());

        User user = new User();
        user.setName(dto.name());
        user.setEmail(dto.email());
        user.setPassword(passwordEncoder.encode(dto.password()));
        user.setUsername(dto.username());
        user.setCreatedAt(Instant.now());
        user.setEnabled(true);
        user.getRoles().addAll(roles);
        repository.save(user);
    }

    public void recoverPassword(EmailDTO dto) {
        UUID uuid = UUID.randomUUID();
        log.info("Recovering password: {}\nEmail: {}", uuid, dto.email());

        Optional<User> user = repository.findByEmail(dto.email());

        if (user.isEmpty()) {
            log.error("Email not found: {}", uuid);
            throw new ResourceNotFoundException("Email não encontrado.");
        }

        String token = UUID.randomUUID().toString();

        PasswordRecoverToken passwordRecoverToken = new PasswordRecoverToken();
        passwordRecoverToken.setEmail(dto.email());
        passwordRecoverToken.setToken(token);
        passwordRecoverToken.setCreatedAt(Instant.now());
        passwordRecoverToken.setExpiration(Instant.now().plusSeconds(tokenExpirationTime * 60L));

        passwordRecoverTokenRepository.save(passwordRecoverToken);

        String uri = recoverUri + "/" + token;

//        TODO: Implement email service
//        emailService.sendPasswordRecoverEmail(email.getEmail(), uri, uuid);
    }

    @Transactional
    public void resetPassword(ResetPasswordDTO dto) {
        UUID uuid = UUID.randomUUID();
        log.info("resetPassword: {}\nEmail: {}", uuid, dto.token());

        List<PasswordRecoverToken> tokens = passwordRecoverTokenRepository.findValidTokens(dto.token(), Instant.now());

        if (tokens.isEmpty()) {
            log.error("Token not found: {}", uuid);
            throw new ResourceNotFoundException("Token inválido.");
        }

        String email = tokens.get(0).getEmail();
        log.info("Token found: {}\nToken Email: {}", uuid, email);

        Optional<User> user = repository.findByEmail(email);
        if (user.isEmpty()) {
            log.error("User not found: {}", uuid);
            throw new ResourceNotFoundException("Usuário não encontrado.");
        }

        if (!user.get().isEnabled()) {
            log.error("User not enabled: {}", uuid);
            throw new ResourceNotFoundException("Usuário não pode acessar sua conta. Entre em contato com o suporte.");
        }

        User userNewPassword = user.get();
        userNewPassword.setPassword(passwordEncoder.encode(dto.password()));
        repository.save(userNewPassword);
    }

    public TokenResponseDTO refreshToken(TokenRefreshTokenDTO dto, HttpServletRequest request) {
        UUID uuid = UUID.randomUUID();
        log.info("refreshToken: {}", uuid);

        try {
            String refreshToken = dto.refreshToken();
            Algorithm algorithm = Algorithm.HMAC512(accessTokenSecret);
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = verifier.verify(refreshToken);
            String username = decodedJWT.getSubject();
            User user = repository.findByUsernameAndRoles(username).orElseThrow(() -> {
                log.error("User not found: {}", uuid);
                return new ResourceNotFoundException("Usuário não encontrado.");
            });

            if (!user.isEnabled()) {
                log.error("User not enabled: {}", uuid);
                throw new IllegalArgumentException("Usuário não pode acessar sua conta. Entre em contato com o suporte.");
            }

            String accessToken = JWT.create()
                    .withSubject(user.getUsername())
                    .withExpiresAt(Date.from(Instant.now().plusSeconds(accessTokenDuration)))
                    .withIssuer(request.getRequestURL().toString())
                    .withClaim(
                            "roles",
                            user.getAuthorities()
                                    .stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())
                    )
                    .sign(Algorithm.HMAC512(accessTokenSecret));

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(username, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            return new TokenResponseDTO(accessToken, refreshToken, Instant.now().plusSeconds(accessTokenDuration).toString());

        } catch (JWTVerificationException e) {
            throw new ForbiddenException("Token inválido.");
        } catch (Exception e) {
            throw new IllegalArgumentException("Token inválido.");
        }

    }

    public void validateSelfOrAdmin(Long userId) {
        User me = authenticated();
        if (!me.hasRole(RolesENUM.ADMIN.getValue()) && !me.getId().equals(userId)) {
            throw new IllegalArgumentException("Não autorizado");
        }
    }

    protected User authenticated() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = repository.findUserByUsername(username).orElseThrow(() -> new ResourceNotFoundException("Usuário não encontrado."));
        return user;
    }

}
