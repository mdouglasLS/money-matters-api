package com.daroz.money_matters_api.config.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter
@Setter
public class CustomUser extends User {

    private Long id;
    private String name;

    public CustomUser(Long id, String username, String name, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.id = id;
        this.name = name;
    }

    public CustomUser(com.daroz.money_matters_api.data.models.User user,  boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked) {
        super(user.getUsername(), user.getPassword(), user.isEnabled(), accountNonExpired, credentialsNonExpired, accountNonLocked, user.getAuthorities());
        this.id = user.getId();
        this.name = user.getName();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
