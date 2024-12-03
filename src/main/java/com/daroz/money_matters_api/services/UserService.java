package com.daroz.money_matters_api.services;

import com.daroz.money_matters_api.data.dtos.UserDTO;
import com.daroz.money_matters_api.data.models.User;
import com.daroz.money_matters_api.repositories.UserRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true)
@Service
public class UserService {

    @Autowired
    private UserRepository repository;

    @Autowired
    private AuthService authService;

    @Autowired
    private ModelMapper modelMapper;


    public UserDTO getMe() {
        User user = authService.authenticated();
        return new UserDTO(user.getId(), user.getName(), user.getUsername(), user.getEmail(), user.getCreatedAt());
//        return modelMapper.map(user, UserDTO.class);
    }
}
