package com.daroz.money_matters_api.services;

import com.daroz.money_matters_api.data.dtos.RoleDTO;
import com.daroz.money_matters_api.data.dtos.UserDTO;
import com.daroz.money_matters_api.data.dtos.UserRegisterDTO;
import com.daroz.money_matters_api.data.models.Role;
import com.daroz.money_matters_api.data.models.User;
import com.daroz.money_matters_api.repositories.RoleRepository;
import com.daroz.money_matters_api.repositories.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Slf4j
@Transactional(readOnly = true)
@Service
public class UserService {

    @Autowired
    private UserRepository repository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private AuthService authService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private ModelMapper modelMapper;

    public UserDTO getMe() {
        User user = authService.authenticated();
        return new UserDTO(user.getId(), user.getName(), user.getUsername(), user.getEmail(), user.getCreatedAt());
//        return modelMapper.map(user, UserDTO.class);
    }

    @Transactional
    public UserDTO createUser(UserRegisterDTO dto) {
        String authenticated = authService.authenticated().getUsername();
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
        user = repository.save(user);

        return new UserDTO(
                user.getId(),
                user.getName(),
                user.getUsername(),
                user.getEmail(),
                user.getCreatedAt()
        );
    }

}
