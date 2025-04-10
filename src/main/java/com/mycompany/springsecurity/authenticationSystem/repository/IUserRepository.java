package com.mycompany.springsecurity.authenticationSystem.repository;

import com.mycompany.springsecurity.authenticationSystem.model.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IUserRepository extends JpaRepository<UserEntity, Long> {


    Optional<UserEntity> findUserEntityByUsername (String username);

    boolean existsByUsername(String username);
}
