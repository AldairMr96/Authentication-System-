package com.mycompany.springsecurity.authenticationSystem.service.test;

import com.jayway.jsonpath.internal.function.text.Concatenate;
import com.mycompany.springsecurity.authenticationSystem.dto.AuthCreateRoleRequest;
import com.mycompany.springsecurity.authenticationSystem.dto.AuthCreateUserRequest;
import com.mycompany.springsecurity.authenticationSystem.dto.AuthLoginRequest;
import com.mycompany.springsecurity.authenticationSystem.dto.AuthResponse;
import com.mycompany.springsecurity.authenticationSystem.model.*;
import com.mycompany.springsecurity.authenticationSystem.repository.IRoleRepository;
import com.mycompany.springsecurity.authenticationSystem.repository.IUserRepository;
import com.mycompany.springsecurity.authenticationSystem.service.UserService;
import com.mycompany.springsecurity.authenticationSystem.util.JwtUtils;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UserServiceTest {

    @Mock
    private IUserRepository userRepository;

    @Mock
    private IRoleRepository roleRepository;

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private PasswordEncoder passwordEncoder;


    @Mock
    private AuthenticationManager authManager;


    @InjectMocks
    private UserService userService;


    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testLoadUserByUsernameUserExists() {
        // Arrange
        String username = "testUser";
        Role mockRole = new Role();
        mockRole.setRoleTypeEnum(RolesEnum.USER);
        Permission permission = new Permission(1L, "READ", null);
        RolePermission rolePermission = new RolePermission(1L, mockRole, permission);
        mockRole.setRolePermissions(Set.of(rolePermission));
        UserEntity mockUser = new UserEntity();
        mockUser.setUsername(username);
        mockUser.setPassword("password");
        mockUser.setIsEnable(true);
        mockUser.setAccountNoExpired(true);
        mockUser.setCreadentialNoExpired(true);
        mockUser.setAccountNoLocked(true);
        mockUser.setRoleType(mockRole);
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_".concat(mockUser.getRoleType().getRoleTypeEnum().name())));
        mockUser.getRoleType().getRolePermissions()
                .forEach(rolePermissionFinding -> authorities.add(new SimpleGrantedAuthority(rolePermission.getPermission().getNamePermission())));

        User userDetail = new User(
                mockUser.getUsername(),
                mockUser.getPassword(),
                mockUser.getIsEnable(),
                mockUser.getAccountNoExpired(),
                mockUser.getCreadentialNoExpired(),
                mockUser.getAccountNoLocked(),
                authorities
        );



        when(userRepository.findUserEntityByUsername(username)).thenReturn(Optional.of(mockUser));

        // Act
        var result = userService.loadUserByUsername(username);

        // Assert
        assertNotNull(result);
        assertEquals(username, result.getUsername());
        verify(userRepository, times(1)).findUserEntityByUsername(username);
    }

    @Test
    void testLoadUserByUsernameUserNotFound() {
        // Arrange
        String username = "nonexistentUser";
        when(userRepository.findUserEntityByUsername(username)).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(BadCredentialsException.class, () -> userService.loadUserByUsername(username));
        verify(userRepository, times(1)).findUserEntityByUsername(username);
    }

    @Test
    void testCreateUserSuccess() {
        // Arrange
        String username = "testUser";
        String rawPassword = "password";
        String encodedPassword = "encodedPassword";


        Role mockRole = new Role();
        mockRole.setRoleTypeEnum(RolesEnum.USER);

        Permission permission = new Permission(1L, "READ", null);
        RolePermission rolePermission = new RolePermission(1L, mockRole, permission);
        mockRole.setRolePermissions(Set.of(rolePermission));

        UserEntity mockUserEntity = new UserEntity();
        mockUserEntity.setUsername(username);
        mockUserEntity.setPassword(encodedPassword);
        mockUserEntity.setIsEnable(true);
        mockUserEntity.setAccountNoExpired(true);
        mockUserEntity.setCreadentialNoExpired(true);
        mockUserEntity.setAccountNoLocked(true);
        mockUserEntity.setRoleType(mockRole);

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + mockUserEntity.getRoleType().getRoleTypeEnum().name()));
        mockUserEntity.getRoleType().getRolePermissions()
                .forEach(rolePermissionFinding -> authorities.add(new SimpleGrantedAuthority(rolePermissionFinding.getPermission().getNamePermission())));

        User userDetail = new User(
                mockUserEntity.getUsername(),
                mockUserEntity.getPassword(),
                mockUserEntity.getIsEnable(),
                mockUserEntity.getAccountNoExpired(),
                mockUserEntity.getCreadentialNoExpired(),
                mockUserEntity.getAccountNoLocked(),
                authorities
        );
        AuthCreateUserRequest request = new AuthCreateUserRequest(username, rawPassword, new AuthCreateRoleRequest(mockRole.getRoleTypeEnum().name()));

        // Configurar comportamiento de los mocks
        when(userRepository.existsByUsername(username)).thenReturn(false);
        when(roleRepository.findByRoleTypeEnum(mockRole.getRoleTypeEnum())).thenReturn(Optional.of(mockRole));
        when(passwordEncoder.encode(rawPassword)).thenReturn(encodedPassword);
        when(userRepository.findUserEntityByUsername(username)).thenReturn(Optional.of(mockUserEntity));
        when(jwtUtils.createToken(anyString(), anyString())).thenReturn("token");

        // Act
        AuthResponse authResponse = userService.createUser(request);

        // Assert
        verify(userRepository, times(1)).save(any(UserEntity.class));
        assertEquals(username, authResponse.username());
        assertEquals("User created successfully", authResponse.message());
        assertEquals("token", authResponse.jwt());
        assertTrue(authResponse.status());
    }

    @Test
    void testCreateUserUserAlreadyExists() {
        // Arrange
        String username = "existingUser";
        RolesEnum roleEnum = RolesEnum.USER;
        AuthCreateUserRequest request = new AuthCreateUserRequest(username, "password",new AuthCreateRoleRequest(roleEnum.name()));
        when(userRepository.existsByUsername(username)).thenReturn(true);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> userService.createUser(request));
        verify(userRepository, never()).save(any(UserEntity.class));
    }

    @Test
    void testCreateUserRoleNotFound (){
        // Datos de prueba
        String username = "newUser";
        String rawPassword = "password";
        RolesEnum roleEnum = RolesEnum.USER;

        AuthCreateUserRequest request = new AuthCreateUserRequest(username, rawPassword,
                new AuthCreateRoleRequest(roleEnum.name()));



        // Configuración de los mocks
        when(userRepository.existsByUsername("testUser")).thenReturn(false); // El usuario no existe
        when(roleRepository.findByRoleTypeEnum(RolesEnum.USER)).thenReturn(Optional.empty()); // Simulación de rol no encontrado

        // Ejecución y verificación de excepción
        EntityNotFoundException exception = Assertions.assertThrows(
                EntityNotFoundException.class,
                () -> userService.createUser(request)
        );

        Assertions.assertEquals("Role not found", exception.getMessage());
        verify(userRepository, never()).save(any());


            }


    @Test
    void testLoginUserSuccess() {
        // Arrange
        String username = "testUser";
        String password = "password";
        String token = "jwtToken";


        Role mockRole = new Role();
        mockRole.setRoleTypeEnum(RolesEnum.USER);
        mockRole.setRolePermissions(Set.of());




        AuthenticationManager authManager = mock(AuthenticationManager.class);
        Authentication authentication = mock(Authentication.class);

        when(authentication.isAuthenticated()).thenReturn(true);
        when(authManager.authenticate(any(Authentication.class))).thenReturn(authentication);

        AuthLoginRequest loginRequest = new AuthLoginRequest(username, password);


        UserEntity mockUser = new UserEntity();
        mockUser.setUsername(username);
        mockUser.setPassword("encodedPassword");
        mockUser.setRoleType(mockRole);
        mockUser.setIsEnable(true);
        mockUser.setAccountNoLocked(true);
        mockUser.setAccountNoExpired(true);
        mockUser.setCreadentialNoExpired(true);
        String authorities = "ROLE_" + mockUser.getRoleType().getRoleTypeEnum().name();

        when(userRepository.findUserEntityByUsername(username)).thenReturn(Optional.of(mockUser));
        when(passwordEncoder.matches(password, mockUser.getPassword())).thenReturn(true);
        when(jwtUtils.createToken(username, authorities)).thenReturn(token);

        // Act
        AuthResponse authResponse = userService.loginUser(loginRequest, authManager);

        // Assert
        assertNotNull(authResponse);
        assertEquals(username, authResponse.username());
        verify(jwtUtils, times(1)).createToken(username, authorities);
        verify(userRepository, times(1)).findUserEntityByUsername(username);
        verify(authManager, times(1)).authenticate(any(Authentication.class));
    }

    @Test
    void testLoginUserInvalidPassword() {
        String username = "testUser";
        String password = "password";
        String token = "jwtToken";


        Role mockRole = new Role();
        mockRole.setRoleTypeEnum(RolesEnum.USER);
        mockRole.setRolePermissions(Set.of());




        AuthenticationManager authManager = mock(AuthenticationManager.class);
        Authentication authentication = mock(Authentication.class);

        when(authentication.isAuthenticated()).thenReturn(true);
        when(authManager.authenticate(any(Authentication.class))).thenReturn(authentication);

        AuthLoginRequest loginRequest = new AuthLoginRequest(username, password);


        UserEntity mockUser = new UserEntity();
        mockUser.setUsername(username);
        mockUser.setPassword("encodedPassword");
        mockUser.setRoleType(mockRole);
        mockUser.setIsEnable(true);
        mockUser.setAccountNoLocked(true);
        mockUser.setAccountNoExpired(true);
        mockUser.setCreadentialNoExpired(true);
        String authorities = "ROLE_" + mockUser.getRoleType().getRoleTypeEnum().name();

        when(userRepository.findUserEntityByUsername(username)).thenThrow(new BadCredentialsException("Invalid username or password"));
        when(passwordEncoder.matches(password, mockUser.getPassword())).thenReturn(false);



        // Act & Assert
        BadCredentialsException exception = assertThrows(
                BadCredentialsException.class,
                () -> userService.loginUser(loginRequest, authManager)
        );

        assertEquals("Invalid username or password", exception.getMessage());


        verify(userRepository, times(1)).findUserEntityByUsername(username);
        verify(passwordEncoder, never()).matches(password, mockUser.getPassword());

    }
    @Test
    void testGetUser() {
        // Arrange
        List<UserEntity> mockUsers = List.of(new UserEntity(), new UserEntity());
        when(userRepository.findAll()).thenReturn(mockUsers);

        // Act
        List<UserEntity> users = userService.getUser();

        // Assert
        assertNotNull(users, "Users list should not be null");
        assertEquals(2, users.size(), "Users list size should match the expected value");
        verify(userRepository, times(1)).findAll();
    }
    @Test
    void testFindUserByIdSuccess() {
        // Arrange
        Long userId = 1L;
        UserEntity mockUser = new UserEntity();
        when(userRepository.findById(userId)).thenReturn(Optional.of(mockUser));

        // Act
        UserEntity user = userService.finUserById(userId);

        // Assert
        assertNotNull(user, "UserEntity should not be null");
        verify(userRepository, times(1)).findById(userId);
    }

    @Test
    void testFindUserByIdNotFound() {
        // Arrange
        Long userId = 1L;
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        // Act & Assert
        EntityNotFoundException exception = assertThrows(EntityNotFoundException.class,
                () -> userService.finUserById(userId), "Expected EntityNotFoundException for missing user");

        assertEquals("User not found", exception.getMessage(), "Exception message should match");
        verify(userRepository, times(1)).findById(userId);
    }

    @Test
    void testDeleteUserByIdSuccess() {
        // Arrange
        Long userId = 1L;
        when(userRepository.existsById(userId)).thenReturn(true);

        // Act
        userService.deleteUserById(userId);

        // Assert
        verify(userRepository, times(1)).deleteById(userId);
    }

    @Test
    void testDeleteUserByIdNotFound() {
        // Arrange
        Long userId = 1L;
        when(userRepository.existsById(userId)).thenReturn(false);

        // Act & Assert
        EntityNotFoundException exception = assertThrows(EntityNotFoundException.class,
                () -> userService.deleteUserById(userId), "Expected EntityNotFoundException for missing user");

        assertEquals("User not found", exception.getMessage(), "Exception message should match");
        verify(userRepository, never()).deleteById(anyLong());
    }
    @Test
    void testEditUserSuccess() {
        // Arrange
        UserEntity mockUser = new UserEntity();
        mockUser.setUsername("testUser");
        mockUser.setPassword("oldPassword");
        mockUser.setIsEnable(false);
        mockUser.setAccountNoExpired(false);
        mockUser.setAccountNoLocked(false);
        mockUser.setCreadentialNoExpired(false);

        UserEntity updatedUser = new UserEntity();
        updatedUser.setUsername("testUser");
        updatedUser.setPassword("newPassword");
        updatedUser.setIsEnable(true);
        updatedUser.setAccountNoExpired(true);
        updatedUser.setAccountNoLocked(true);
        updatedUser.setCreadentialNoExpired(true);

        String encodedPassword = "encodedNewPassword";

        when(userRepository.findUserEntityByUsername(updatedUser.getUsername())).thenReturn(Optional.of(mockUser));
        when(passwordEncoder.encode("newPassword")).thenReturn(encodedPassword);
        when(userRepository.save(mockUser)).thenReturn(mockUser);

        // Act
        UserEntity result = userService.editUser(updatedUser);

        // Assert
        verify(passwordEncoder, times(1)).encode("newPassword");
        verify(userRepository, times(1)).findUserEntityByUsername(updatedUser.getUsername());
        verify(userRepository, times(1)).save(mockUser);

        assertNotNull(result, "Updated UserEntity should not be null");
        assertEquals(encodedPassword, result.getPassword(), "Password should be updated with the encoded password");
        assertTrue(result.getIsEnable(), "User should be enabled");
        assertTrue(result.getAccountNoExpired(), "Account should not be expired");
        assertTrue(result.getAccountNoLocked(), "Account should not be locked");
        assertTrue(result.getCreadentialNoExpired(), "Credential should not be expired");
    }

    @Test
    void testEditUserNotFound() {
        // Arrange
        UserEntity updatedUser = new UserEntity();
        updatedUser.setUsername("testUser");

        when(userRepository.findUserEntityByUsername(updatedUser.getUsername())).thenReturn(Optional.empty());

        // Act & Assert
        EntityNotFoundException exception = assertThrows(EntityNotFoundException.class,
                () -> userService.editUser(updatedUser), "Expected EntityNotFoundException for missing user");

        assertEquals("User not found", exception.getMessage(), "Exception message should match");
        verify(userRepository, times(1)).findUserEntityByUsername(updatedUser.getUsername());
        verify(userRepository, never()).save(any());
    }
    @Test
    void testEditUserPasswordNull (){
        // Datos de prueba
        UserEntity inputUser = new UserEntity();
        inputUser.setUsername("testUser");
        inputUser.setPassword(null); // Sin contraseña
        inputUser.setIsEnable(true);
        inputUser.setAccountNoExpired(true);
        inputUser.setAccountNoLocked(true);
        inputUser.setCreadentialNoExpired(true);

        UserEntity existingUser = new UserEntity();
        existingUser.setUsername("testUser");
        existingUser.setPassword("oldPassword");
        existingUser.setIsEnable(false);
        existingUser.setAccountNoExpired(false);
        existingUser.setAccountNoLocked(false);
        existingUser.setCreadentialNoExpired(false);


        when(userRepository.findUserEntityByUsername("testUser")).thenReturn(Optional.of(existingUser));


        UserEntity updatedUser = userService.editUser(inputUser);


       verify(userRepository).findUserEntityByUsername("testUser");
       verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository).save(existingUser);

        Assertions.assertEquals("oldPassword", updatedUser.getPassword());
        Assertions.assertTrue(updatedUser.getIsEnable());
        Assertions.assertTrue(updatedUser.getAccountNoExpired());
        Assertions.assertTrue(updatedUser.getAccountNoLocked());
        Assertions.assertTrue(updatedUser.getCreadentialNoExpired());
    }
    @Test
    void testEditUserPasswordEmpty (){
        // Datos de prueba
        UserEntity inputUser = new UserEntity();
        inputUser.setUsername("testUser");
        inputUser.setPassword("");
        inputUser.setIsEnable(true);
        inputUser.setAccountNoExpired(true);
        inputUser.setAccountNoLocked(true);
        inputUser.setCreadentialNoExpired(true);

        UserEntity existingUser = new UserEntity();
        existingUser.setUsername("testUser");
        existingUser.setPassword("oldPassword");
        existingUser.setIsEnable(false);
        existingUser.setAccountNoExpired(false);
        existingUser.setAccountNoLocked(false);
        existingUser.setCreadentialNoExpired(false);


        when(userRepository.findUserEntityByUsername("testUser")).thenReturn(Optional.of(existingUser));


        UserEntity updatedUser = userService.editUser(inputUser);


        verify(userRepository, times(1)).findUserEntityByUsername("testUser");
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository).save(existingUser);

        Assertions.assertEquals("oldPassword", updatedUser.getPassword());
        Assertions.assertTrue(updatedUser.getIsEnable());
        Assertions.assertTrue(updatedUser.getAccountNoExpired());
        Assertions.assertTrue(updatedUser.getAccountNoLocked());
        Assertions.assertTrue(updatedUser.getCreadentialNoExpired());
    }



    @Test
    void testAuthenticateSuccess() {
        // Arrange
        String username = "testUser";
        String password = "testPassword";
        Role mockRole = new Role();
        mockRole.setRoleTypeEnum(RolesEnum.USER);
        mockRole.setRolePermissions(Set.of());
        UserEntity userEntity = new UserEntity(
                1L, username, "encodedPassword",
                true, true, true, true, mockRole);

        // Configura el mock para loadUserByUsername
        when(userRepository.findUserEntityByUsername(username)).thenReturn(
                java.util.Optional.of(userEntity)
        );
        when(passwordEncoder.matches(password, "encodedPassword")).thenReturn(true);

        // Act
        UsernamePasswordAuthenticationToken result = (UsernamePasswordAuthenticationToken) userService.authenticate(username, password);

        // Assert
        assertNotNull(result, "El resultado no debe ser nulo");
        assertEquals(username, result.getPrincipal(), "El principal debe ser el nombre de usuario");
        assertEquals("encodedPassword", result.getCredentials(), "Las credenciales deben coincidir con la contraseña codificada");
    }

    @Test
    void testAuthenticateInvalidPassword() {
        // Arrange
        String username = "testUser";
        String password = "wrongPassword";
        Role mockRole = new Role();
        mockRole.setRoleTypeEnum(RolesEnum.USER);
        mockRole.setRolePermissions(Set.of());
        UserEntity userEntity = new UserEntity(
                1L, username, "encodedPassword",
                true, true, true, true, mockRole);
        // Configura el mock para loadUserByUsername
        when(userRepository.findUserEntityByUsername(username)).thenReturn(
                java.util.Optional.of(userEntity)
        );
        when(passwordEncoder.matches(password, "encodedPassword")).thenReturn(false);

        // Act & Assert
        BadCredentialsException exception = assertThrows(
                BadCredentialsException.class,
                () -> userService.authenticate(username, password),
                "Invalid  password"
        );

        assertEquals("Invalid  password", exception.getMessage(), "Invalid  password");
    }

    @Test
    void testAuthenticateUserNotFound() {
        // Arrange
        String username = "nonExistentUser";
        String password = "testPassword";

        // Configura el mock para loadUserByUsername
        when(userRepository.findUserEntityByUsername(username)).thenReturn(java.util.Optional.empty());


        // Act & Assert
        BadCredentialsException exception = assertThrows(
                BadCredentialsException.class,
                () -> userService.authenticate(username, password),
                "Invalid username or password"
        );

        assertEquals("Invalid username or password", exception.getMessage(), "Invalid username or password");
    }
}
