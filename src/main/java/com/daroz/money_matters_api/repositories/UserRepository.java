package com.daroz.money_matters_api.repositories;

import com.daroz.money_matters_api.data.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findUserByUsername(String username);

    @Query("SELECT u FROM User u JOIN FETCH u.roles WHERE u.username = :username")
    Optional<User> findByUsernameAndRoles(String username);

    Optional<User> findByEmail(String email);

    @Query("SELECT COUNT(p.id) < 1 FROM User p WHERE p.username = :username")
    boolean checkUsernameAvailable(String username);

    @Query("SELECT COUNT(p.id) < 1 FROM User p WHERE p.email = :email")
    boolean checkEmailAvailable(String email);
}
