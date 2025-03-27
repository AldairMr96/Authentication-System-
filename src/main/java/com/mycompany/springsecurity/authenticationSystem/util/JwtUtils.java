package com.mycompany.springsecurity.authenticationSystem.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    @Value("${security.jwt.key}")
    private String privateKey;
    @Value("${security.jwt.user.generator}")
    private String userGenerator;

    private static  final long EXPIRATION_TIME = 1800000;

    public String createToken(String username, String authorities){

            return JWT.create()
                    .withSubject(username)
                    .withClaim("authorities", authorities)
                    .withExpiresAt(new Date(System.currentTimeMillis()+ EXPIRATION_TIME))
                    .sign(Algorithm.HMAC256(privateKey))
                    ;
    }

    public String extractUsername(String token) {
        return JWT.require(Algorithm.HMAC256(privateKey))
                .build()
                .verify(token)
                .getSubject()
                ;
    }
    public Boolean verifyToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public boolean isTokenExpired (String token){
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC256(privateKey))
                .build()
                .verify(token);
        return decodedJWT.getExpiresAt().before(new Date());
    }
    public String extractAuthorities(String token) {
        return JWT.require(Algorithm.HMAC256(privateKey))
                .build()
                .verify(token)
                .getClaim("authorities").asString();
    }


}
