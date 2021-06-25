package com.shane.authentication.repository;

import com.shane.authentication.entity.user.AuthType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface AuthTypeRepository extends JpaRepository<AuthType, Integer>, JpaSpecificationExecutor<AuthType> {

}