package com.mycompany.springsecurity.authenticationSystem.service;

import com.mycompany.springsecurity.authenticationSystem.dto.AuthCreateUserRequest;
import com.mycompany.springsecurity.authenticationSystem.dto.AuthLoginRequest;
import com.mycompany.springsecurity.authenticationSystem.dto.AuthResponse;
import com.mycompany.springsecurity.authenticationSystem.model.UserEntity;
import org.springframework.security.authentication.AuthenticationManager;

import java.util.List;

public interface IUserService {
    public  AuthResponse createUser (AuthCreateUserRequest authCreateUserRequest);

    public List<UserEntity> getUser();

    public UserEntity finUserById (Long idUserEntity);

    public void deleteUserById (Long idUserEntity);

    public UserEntity editUser (UserEntity userEntity);
    public AuthResponse loginUser (AuthLoginRequest authLoginRequest, AuthenticationManager authenticationManager);


}
