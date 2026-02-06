package com.northstar.northstar.auth.service.mapper;

import com.northstar.northstar.auth.service.dto.response.user.UserResponse;
import com.northstar.northstar.auth.service.entity.UserEntity;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring", uses = RoleMapper.class)
public interface UserMapper {

    @Mapping(target = "roles", source = "roles")
    UserResponse createUserResponseFromUserEntity(UserEntity userEntity);
}
