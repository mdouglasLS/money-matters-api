package com.daroz.money_matters_api.resources;

import com.daroz.money_matters_api.data.dtos.UserDTO;
import com.daroz.money_matters_api.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

}
