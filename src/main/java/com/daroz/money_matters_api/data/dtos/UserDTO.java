package com.daroz.money_matters_api.data.dtos;

import java.time.Instant;

public record UserDTO (
        Long id,
        String name,
        String username,
        String email,
        Instant createdAt
){
}
