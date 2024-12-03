package com.daroz.money_matters_api.data.dtos;

import com.daroz.money_matters_api.data.models.Role;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

import java.util.List;

public record UserRegisterDTO (
        @NotBlank(message = "Campo Nome é obrigatório.")
        @Size(min = 5, max = 255, message = "É necessário informar um nome entre 5 e 255 caracteres.")
        String name,

        @NotBlank(message = "Campo Username é obrigatório.")
        @Size(min = 4, max = 255, message = "É necessário informar um username entre 4 e 255 caracteres.")
        String username,

        @NotBlank(message = "Campo Email é obrigatório.")
        @Size(min = 5, max = 255, message = "É necessário informar um email entre 5 e 255 caracteres.")
        @Email(message = "É necessário informar um e-mail válido.")
        String email,

        @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
        @NotBlank(message = "Campo Senha é obrigatório.")
        @Size(min = 8, max = 30, message = "É necessário informar uma senha 8 e 30 caracteres.")
        @Pattern(regexp = "^[^\\s]*$", message = "Senha não pode conter espaços.")
        String password,

        @NotNull(message = "Campo Role é obrigatório.")
        @NotEmpty(message = "Campo Role é obrigatório.")
        @Valid
        List<RoleDTO> roles
){
}
