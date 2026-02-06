package com.northstar.northstar.auth.service.repository;

import com.northstar.northstar.auth.service.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Optional<UserEntity> findByUid(String uid);

    Optional<UserEntity> findUserByUsername(String username);
}
