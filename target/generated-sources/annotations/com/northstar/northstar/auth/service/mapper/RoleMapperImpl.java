package com.northstar.northstar.auth.service.mapper;

import com.northstar.northstar.auth.service.dto.response.role.RoleResponse;
import com.northstar.northstar.auth.service.entity.RoleEntity;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2026-02-06T15:28:30+0000",
    comments = "version: 1.6.3, compiler: javac, environment: Java 21.0.4 (Azul Systems, Inc.)"
)
@Component
public class RoleMapperImpl implements RoleMapper {

    @Override
    public RoleResponse convertRoleEntityToRoleResponse(RoleEntity role) {
        if ( role == null ) {
            return null;
        }

        RoleResponse.RoleResponseBuilder roleResponse = RoleResponse.builder();

        roleResponse.id( role.getId() );
        roleResponse.name( role.getName() );
        roleResponse.description( role.getDescription() );

        return roleResponse.build();
    }
}
