package com.daroz.money_matters_api.data.dtos;

import jakarta.validation.constraints.NotNull;

public record RoleDTO(
        @NotNull(message = "Campo ID da role é obrigatório.")
        Long id,
        String name
) {
}
