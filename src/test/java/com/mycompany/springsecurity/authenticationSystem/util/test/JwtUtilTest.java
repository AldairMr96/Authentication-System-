package com.mycompany.springsecurity.authenticationSystem.util.test;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mycompany.springsecurity.authenticationSystem.util.JwtUtils;
import jakarta.validation.constraints.AssertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class JwtUtilTest {
    @Mock
    private UserDetails userDetails;

    @InjectMocks
    private JwtUtils jwtUtils;

    private final String privateKey = "my_secret_key"; // Simula la clave secreta del JWT
    private final String username = "testUser";
    private final String authorities = "ROLE_USER";
    private String token ;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        ReflectionTestUtils.setField(jwtUtils, "privateKey", privateKey);

        // Generar un token de prueba
        token = jwtUtils.createToken(username, authorities);
    }
    @Test
    void testCreateTokenSuccess() {
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void testExtractUsernameSuccess() {
        String extractedUsername = jwtUtils.extractUsername(token);
        assertEquals(username, extractedUsername);
    }
    @Test
    void testVerifyToken_ValidToken() {

       String username = "test_user";
       when(userDetails.getUsername()).thenReturn(username);

        String validToken = JWT.create()
                .withSubject(userDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 60000)) // 1 min de validez
                .sign(Algorithm.HMAC256(privateKey));


        // Act & Assert
        assertTrue(jwtUtils.verifyToken(validToken, userDetails));
    }

    @Test
    void testVerifyToken_ExpiredToken() {
        // Arrange: Crear un token expirado

        String expiredToken = JWT.create()
                .withSubject(userDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() - 1000)) // Ya expirado
                .sign(Algorithm.HMAC256(privateKey));

        // Act & Assert
        assertFalse(jwtUtils.verifyToken(expiredToken, userDetails));
    }

    @Test
    void testVerifyToken_InvalidSignature() {
        // Arrange: Crear un token con firma incorrecta
        String invalidToken = JWT.create()
                .withSubject(userDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 60000))
                .sign(Algorithm.HMAC256("wrong_secret")); // ❌ Firma incorrecta

        // Act & Assert
        assertThrows(JWTVerificationException.class, () -> jwtUtils.verifyToken(invalidToken, userDetails));
    }

    @Test
    void testVerifyToken_MalformedToken() {
        // Arrange: Token mal formado
        String malformedToken = "invalid.token.string";

        // Act & Assert
        assertThrows(JWTDecodeException.class, () -> jwtUtils.verifyToken(malformedToken, userDetails));
    }

    @Test
    void testVerifyToken_InvalidUser() {
        // Arrange: Token con un usuario diferente
        String tokenWithWrongUser = JWT.create()
                .withSubject("wrong_user") // Usuario incorrecto
                .withExpiresAt(new Date(System.currentTimeMillis() + 60000))
                .sign(Algorithm.HMAC256(privateKey));

        // Act & Assert
        assertFalse(jwtUtils.verifyToken(tokenWithWrongUser, userDetails));
    }

    @Test
    void testIsTokenExpiredFalse() {
        assertFalse(jwtUtils.isTokenExpired(token));
    }

    @Test
    void testExtractAuthoritiesSuccess() {
        String extractedAuthorities = jwtUtils.extractAuthorities(token);
        assertEquals(authorities, extractedAuthorities);
    }

    @Test
    void testInvalidTokenThrowsException() {
        String invalidToken = token + "invalid";

        assertThrows(JWTVerificationException.class, () -> {
            jwtUtils.extractUsername(invalidToken);
        });
    }



}
