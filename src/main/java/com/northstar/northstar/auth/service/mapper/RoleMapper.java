package com.northstar.northstar.auth.service.mapper;

import com.northstar.northstar.auth.service.dto.response.role.RoleResponse;
import com.northstar.northstar.auth.service.entity.RoleEntity;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface RoleMapper {

    RoleResponse convertRoleEntityToRoleResponse(RoleEntity role);
}
