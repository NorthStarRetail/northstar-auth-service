package com.northstar.northstar.auth.service.impl;

import com.northstar.northstar.auth.service.dto.request.role.RoleRequest;
import com.northstar.northstar.auth.service.dto.response.role.RoleResponse;
import com.northstar.northstar.auth.service.entity.RoleEntity;
import com.northstar.northstar.auth.service.mapper.RoleMapper;
import com.northstar.northstar.auth.service.repository.RoleRepository;
import com.northstar.northstar.auth.service.service.RoleService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;
    private final RoleMapper roleMapper;

    public RoleServiceImpl(RoleRepository roleRepository, RoleMapper roleMapper) {
        this.roleRepository = roleRepository;
        this.roleMapper = roleMapper;
    }

    @Override
    @Transactional
    public RoleResponse createRole(RoleRequest request) {
        String roleName = request.getRole().getValue();
        return roleRepository.findByName(roleName)
                .or(() -> Optional.of(roleRepository.save(RoleEntity.builder()
                        .name(roleName)
                        .description(request.getRole().name())
                        .build())))
                .map(roleMapper::convertRoleEntityToRoleResponse)
                .orElseThrow(() -> new RuntimeException("Failed to create or retrieve role"));
    }

    @Override
    public List<RoleResponse> getRoles() {
        return roleRepository.findAll().stream()
                .map(roleMapper::convertRoleEntityToRoleResponse)
                .toList();
    }
}
