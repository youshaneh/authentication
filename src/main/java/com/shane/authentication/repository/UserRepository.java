package com.shane.authentication.repository;

import com.shane.authentication.entity.user.AuthType;
import com.shane.authentication.entity.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {

    @Query(value = "SELECT * FROM user JOIN auth_type ON user.auth_type = auth_type.id WHERE email = ?1 AND auth_type= ?2", nativeQuery = true)
    Optional<User> findByEmailAndAuthType(String email, int authType);
}