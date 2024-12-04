package com.daroz.money_matters_api.resources;

import com.daroz.money_matters_api.data.dtos.auth.EmailDTO;
import com.daroz.money_matters_api.data.dtos.auth.ResetPasswordDTO;
import com.daroz.money_matters_api.data.dtos.auth.TokenRefreshTokenDTO;
import com.daroz.money_matters_api.data.dtos.auth.TokenResponseDTO;
import com.daroz.money_matters_api.services.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/auth")
public class AuthResource {

    @Autowired
    private AuthService service;

    @PostMapping("/refresh-token")
    public ResponseEntity<TokenResponseDTO> refreshToken(@RequestBody @Valid TokenRefreshTokenDTO dto, HttpServletRequest request) {
        TokenResponseDTO response = service.refreshToken(dto, request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/recover-password")
    public ResponseEntity<Void> recoverPassword(@RequestBody @Valid EmailDTO dto) {
        service.recoverPassword(dto);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(@RequestBody @Valid ResetPasswordDTO dto) {
        service.resetPassword(dto);
        return ResponseEntity.noContent().build();
    }

}
