package com.daroz.money_matters_api.data.dtos.auth;

import jakarta.validation.constraints.NotBlank;

public record TokenRefreshTokenDTO(
        @NotBlank(message = "Token de atualização é necessário.")
        String refreshToken
) {
}
