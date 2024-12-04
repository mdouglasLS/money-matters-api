package com.daroz.money_matters_api.resources;

import com.daroz.money_matters_api.data.dtos.UserDTO;
import com.daroz.money_matters_api.data.dtos.UserRegisterDTO;
import com.daroz.money_matters_api.services.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/users")
public class UserResource {

    @Autowired
    private UserService service;

    @GetMapping("/me")
    public ResponseEntity<UserDTO> getMe() {
        UserDTO me = service.getMe();
        return ResponseEntity.ok(me);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/sign-up")
    public ResponseEntity<UserDTO> createUser(@RequestBody @Valid UserRegisterDTO dto) {
        UserDTO userDTO = service.createUser(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(userDTO);
    }

}
