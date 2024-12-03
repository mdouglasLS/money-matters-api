package com.daroz.money_matters_api.data.dtos.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EmailDTO(
        @NotBlank(message = "Campo Email é obrigatório.")
        @Size(min = 5, max = 255, message = "É necessário informar um email entre 5 e 255 caracteres.")
        @Email(message = "É necessário informar um e-mail válido.")
        String email
) {
}
