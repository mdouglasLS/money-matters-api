package com.daroz.money_matters_api.data.dtos.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequestDTO (
        @NotBlank(message = "Username não pode ser em branco.")
        String username,
        @NotBlank(message = "Senha não pode ser em branco.")
        String password
) {
}
