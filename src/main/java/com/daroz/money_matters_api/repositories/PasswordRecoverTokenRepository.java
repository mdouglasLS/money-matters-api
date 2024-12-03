package com.daroz.money_matters_api.repositories;

import com.daroz.money_matters_api.data.models.PasswordRecoverToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface PasswordRecoverTokenRepository extends JpaRepository<PasswordRecoverToken, Long> {

    @Query("SELECT p FROM PasswordRecoverToken p WHERE p.token = :token AND p.expiration > :now")
    List<PasswordRecoverToken> findValidTokens(String token, Instant now);

}
