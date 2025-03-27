package com.mycompany.springsecurity.authenticationSystem.config;

import com.mycompany.springsecurity.authenticationSystem.config.filter.JwtTokenValidator;
import com.mycompany.springsecurity.authenticationSystem.service.UserService;
import com.mycompany.springsecurity.authenticationSystem.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtTokenValidator jwtTokenValidator;
    @Autowired
    private JwtUtils jwtUtils;


    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration,JwtTokenValidator jwtTokenValidator) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtTokenValidator =jwtTokenValidator;
    }
    //configure the security filter chain
    @Bean
    public SecurityFilterChain securityFilterChain (HttpSecurity httpSecurity) throws Exception {

         httpSecurity
                .csrf(csrf -> csrf.disable())
                .headers(headers -> headers.frameOptions(frame -> frame.disable())) // Allow use of frames for H2 Console
                .httpBasic(Customizer.withDefaults()) // Default is user and password
                .sessionManagement(
                        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> {

                    auth.requestMatchers("/h2-console/**").permitAll(); // Allow access to H2 Console
                    auth.requestMatchers(HttpMethod.GET, "/authentication/get").permitAll();
                    auth.requestMatchers(HttpMethod.POST, "/authentication/log-in").permitAll();
                    auth.requestMatchers(HttpMethod.POST, "/authentication/sign-in").permitAll();
                    auth.requestMatchers(HttpMethod.GET, "/authentication/find").hasAnyRole("DEVELOPER", "MANAGER");
                    auth.requestMatchers(HttpMethod.PUT, "/authentication/edit").hasAnyRole("DEVELOPER", "MANAGER");
                    auth.requestMatchers(HttpMethod.DELETE, "/authentication/delete").hasAnyRole("DEVELOPER", "MANAGER");

                    auth.anyRequest().authenticated();
                })
                .addFilterBefore(jwtTokenValidator, BasicAuthenticationFilter.class);

                return httpSecurity.build();
    }


    @Bean
    public AuthenticationManager authenticationManager () throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    @Bean
    public PasswordEncoder passwordEncoder (){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationProvider authenticationProvider(UserService userDetailsServiceImpl){
        DaoAuthenticationProvider dap =  new DaoAuthenticationProvider();
        dap.setPasswordEncoder(passwordEncoder());
        dap.setUserDetailsService(userDetailsServiceImpl);
        return dap ;
    }





}

