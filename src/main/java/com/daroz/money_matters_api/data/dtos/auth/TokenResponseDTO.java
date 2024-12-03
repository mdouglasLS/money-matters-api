package com.daroz.money_matters_api.data.dtos.auth;

public record TokenResponseDTO(
        String accessToken,
        String refreshToken,
        String expiresAt
){
}
