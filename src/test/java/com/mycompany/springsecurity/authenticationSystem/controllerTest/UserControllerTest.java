package com.mycompany.springsecurity.authenticationSystem.controllerTest;

import com.mycompany.springsecurity.authenticationSystem.controller.UserController;
import com.mycompany.springsecurity.authenticationSystem.dto.AuthCreateUserRequest;
import com.mycompany.springsecurity.authenticationSystem.dto.AuthLoginRequest;
import com.mycompany.springsecurity.authenticationSystem.dto.AuthResponse;
import com.mycompany.springsecurity.authenticationSystem.model.UserEntity;
import com.mycompany.springsecurity.authenticationSystem.repository.IUserRepository;
import com.mycompany.springsecurity.authenticationSystem.service.IUserService;
import com.mycompany.springsecurity.authenticationSystem.util.JwtUtils;
import jakarta.persistence.EntityNotFoundException;
import org.hibernate.validator.constraints.ModCheck;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.NOT_FOUND;

public class UserControllerTest {
    @Mock
    private IUserService userService;

    @Mock
    private JwtUtils jwtUtils;
    @Mock
    private  AuthenticationManager authManager;
    @Mock
    private IUserRepository userRepository;

    @InjectMocks
    private UserController userController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testGetUsersSuccess() {
        // Arrange
        UserEntity user1 = new UserEntity();
        UserEntity user2 = new UserEntity();
        List<UserEntity> users = List.of(user1, user2);
        when(userService.getUser()).thenReturn(users);

        // Act
        List<UserEntity> usersResult = userController.getUsers();

        // Assert
        assertNotNull(usersResult);
        assertEquals(2, usersResult.size());
        verify(userService, times(1)).getUser();
    }

    @Test
    void testFindUserByIdSuccess() {
        // Arrange
        Long userId = 1L;
        UserEntity user = new UserEntity();
        when(userService.finUserById(userId)).thenReturn(user);

        // Act
        ResponseEntity<?> response = userController.findUserById(userId);

        // Assert
        assertEquals(200, response.getStatusCodeValue());
        assertEquals(user, response.getBody());
        verify(userService, times(1)).finUserById(userId);
    }

    @Test
    void testFindUserByIdNotFound() {
        // Arrange
        Long userId = 1L;
        when(userService.finUserById(userId)).thenThrow(new EntityNotFoundException("User not found"));

        // Act
        ResponseEntity<?> response = userController.findUserById(userId);

        // Assert
        assertEquals(NOT_FOUND, response.getStatusCode());
        assertEquals("User not found", response.getBody());
        verify(userService, times(1)).finUserById(userId);
    }
    @Test
    void testFindUserByIdInternalError() {

        doThrow(new RuntimeException("Server internal Error")).when(userService).finUserById(1L);

        ResponseEntity<?> response = userController.findUserById(1L);

        assertNotNull(response);
        assertEquals(INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("Server internal Error", response.getBody());

        verify(userService, times(1)).finUserById(1L);

    }
    @Test
    void testCreateUserSuccess() {
        // Arrange
        String username = "user_test";
        String password = "password";
        String token = "token";

        AuthCreateUserRequest userRequest = new AuthCreateUserRequest("user_test",
                "password", null);
        AuthResponse authResponse = new AuthResponse(username, "Create user susccessfully", token, true);

        when(userService.createUser(userRequest)).thenReturn(authResponse);

        // Act
        ResponseEntity<?> response = userController.createUser(userRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(authResponse, response.getBody());
        verify(userService, times(1)).createUser(userRequest);
    }

    @Test
    void testEditUserSuccess() {
        // Arrange
        UserEntity userEntity = new UserEntity();

        // Act
        ResponseEntity<?> response = userController.editUser(userEntity);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("edit user susccessfully ", response.getBody());
        verify(userService, times(1)).editUser(userEntity);
    }

    @Test
    void testEditUserNotFound() {
        // Arrange
        UserEntity userEntity = new UserEntity();
        doThrow(new EntityNotFoundException("User not found")).when(userService).editUser(userEntity);

        // Act
        ResponseEntity<?> response = userController.editUser(userEntity);

        // Assert
        assertEquals(NOT_FOUND, response.getStatusCode());
        assertEquals("User not found", response.getBody());
        verify(userService, times(1)).editUser(userEntity);
    }
    @Test
    void testEditUserInternalError() {
        // Arrange
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername("testUser");
        doThrow(new RuntimeException("Server internal Error")).when(userService).editUser(userEntity);

        // Act
        ResponseEntity<?> response = userController.editUser(userEntity);

        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("Server internal Error", response.getBody());

        verify(userService, times(1)).editUser(userEntity);
    }
    @Test
    void testDeleteUser_Success() {
        // Arrange
        Long userId = 1L;

        // Act
        ResponseEntity<?> response = userController.deleteUser(userId);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Delete user susccessfully", response.getBody());
        verify(userService, times(1)).deleteUserById(userId);
    }

    @Test
    void testDeleteUser_NotFound() {
        // Arrange
        Long userId = 1L;
        doThrow(new EntityNotFoundException("User not found")).when(userService).deleteUserById(userId);

        // Act
        ResponseEntity<?> response = userController.deleteUser(userId);

        // Assert
        assertEquals(NOT_FOUND, response.getStatusCode());
        assertEquals("User not found", response.getBody());
        verify(userService, times(1)).deleteUserById(userId);
    }
    @Test
    void testDeleteUserInternalError() {
        // Arrange
        Long idUserEntity = 1L;
        doThrow(new RuntimeException("Server internal Error")).when(userService).deleteUserById(idUserEntity);

        // Act
        ResponseEntity<?> response = userController.deleteUser(idUserEntity);

        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("Server internal Error", response.getBody());

        verify(userService, times(1)).deleteUserById(idUserEntity);
    }

    @Test
    void testLoginUser_Success() {
        // Arrange
        String username = "test_user";
        String password = "password";

        authManager.authenticate(new UsernamePasswordAuthenticationToken(
                username, password
        ));
        AuthLoginRequest loginRequest = new AuthLoginRequest(username, password);
        AuthResponse authResponse = new AuthResponse(username,  "Login susscessfully",
                "accessToken", true);
        when(userService.loginUser(loginRequest, authManager)).thenReturn(authResponse);

        // Act
        ResponseEntity<?> response = userController.loginUser(loginRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(authResponse, response.getBody());
        verify(userService, times(1)).loginUser(loginRequest, authManager);
    }

    @Test
    void testLoginUser_BadCredentials() {
        // Arrange
        String username = "test_user";
        String password = "password";

        AuthLoginRequest loginRequest = new AuthLoginRequest(username, password);




        when(userRepository.findUserEntityByUsername(username))
                .thenReturn(Optional.empty());

        when(userService.loginUser(loginRequest, authManager))
                .thenThrow(new BadCredentialsException("Invalid username or password"));

        // Act
        ResponseEntity<?> response = userController.loginUser(loginRequest);

        // Assert
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertEquals("Invalid username or password", response.getBody());

       verify(userService, times(1)).loginUser(loginRequest, authManager);
        verify(userRepository, times(0)).findUserEntityByUsername(username);
    }
    @Test
    void testLoginUserInternalError() {
        // Arrange


        AuthLoginRequest loginRequest = new AuthLoginRequest("username", "password");
        doThrow(new RuntimeException("Server internal Error")).when(userService).loginUser(loginRequest, authManager);

        // Act
        ResponseEntity<?> response = userController.loginUser(loginRequest);

        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("Server internal Error", response.getBody());

        verify(userService, times(1)).loginUser(loginRequest, authManager);
    }
}
