package com.northstar.northstar.auth.service.service;

import com.northstar.northstar.auth.service.dto.request.role.RoleRequest;
import com.northstar.northstar.auth.service.dto.response.role.RoleResponse;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface RoleService {

    RoleResponse createRole(RoleRequest request);

    List<RoleResponse> getRoles();
}
