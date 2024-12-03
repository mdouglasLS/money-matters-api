package com.daroz.money_matters_api.data.dtos.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ResetPasswordDTO(
        @NotBlank(message = "Token é obrigatório.")
        String token,

        @NotBlank(message = "Campo senha é obrigatório.")
        @Size(min = 8, message = "Senha deve ter no mínimo 8 caracteres.")
        @Pattern(regexp = "^[^\\s]*$", message = "Senha não deve conter espaços.")
        String password
) {
}
