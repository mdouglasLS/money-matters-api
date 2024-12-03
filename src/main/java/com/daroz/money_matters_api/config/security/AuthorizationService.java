package com.daroz.money_matters_api.config.security;

import com.daroz.money_matters_api.data.models.User;
import com.daroz.money_matters_api.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true)
@Service
public class AuthorizationService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repository.findByUsernameAndRoles(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return new CustomUser(
                user.getId(),
                user.getUsername(),
                user.getName(),
                user.getPassword(),
                true,
                true,
                true,
                true,
                user.getAuthorities()
        );
    }
}
