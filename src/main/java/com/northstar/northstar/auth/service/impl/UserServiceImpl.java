package com.northstar.northstar.auth.service.impl;

import com.northstar.northstar.auth.service.dto.request.user.UserRequest;
import com.northstar.northstar.auth.service.dto.response.user.UserResponse;
import com.northstar.northstar.auth.service.entity.RoleEntity;
import com.northstar.northstar.auth.service.entity.UserEntity;
import com.northstar.northstar.auth.service.exception.RoleNotFoundException;
import com.northstar.northstar.auth.service.exception.UserNotCreatedException;
import com.northstar.northstar.auth.service.exception.UserNotFoundException;
import com.northstar.northstar.auth.service.mapper.UserMapper;
import com.northstar.northstar.auth.service.repository.RoleRepository;
import com.northstar.northstar.auth.service.repository.UserRepository;
import com.northstar.northstar.auth.service.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

@Service
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder,
                           RoleRepository roleRepository, UserMapper userMapper) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.userMapper = userMapper;
    }

    @Override
    public UserResponse createUser(UserRequest request) {
        if (userRepository.findUserByUsername(request.getUsername()).isPresent()) {
            throw new UserNotCreatedException("Username already exists: " + request.getUsername());
        }
        RoleEntity roleEntity = roleRepository.findByName(request.getRole().getValue())
                .orElseThrow(() -> new RoleNotFoundException("Role not found"));
        UserEntity entity = UserEntity.builder()
                .username(request.getUsername())
                .lastname(request.getLastname())
                .firstname(request.getFirstname())
                .password(passwordEncoder.encode(request.getPassword()))
                .createdAt(LocalDateTime.now())
                .roles(Collections.singleton(roleEntity))
                .build();
        UserEntity saved = userRepository.save(entity);
        return userMapper.createUserResponseFromUserEntity(saved);
    }

    @Override
    public UserResponse getUserByUid(String uid) {
        return userRepository.findByUid(uid)
                .map(userMapper::createUserResponseFromUserEntity)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
    }

    @Override
    public UserResponse getUserDetails(String username) {
        return userRepository.findUserByUsername(username)
                .map(userMapper::createUserResponseFromUserEntity)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
    }

    @Override
    public List<UserResponse> getUsers(Pageable pageable) {
        return userRepository.findAll(pageable).getContent().stream()
                .map(userMapper::createUserResponseFromUserEntity)
                .toList();
    }
}
