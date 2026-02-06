package com.northstar.northstar.auth.service.mapper;

import com.northstar.northstar.auth.service.dto.response.user.UserResponse;
import com.northstar.northstar.auth.service.entity.RoleEntity;
import com.northstar.northstar.auth.service.entity.UserEntity;
import java.util.ArrayList;
import java.util.Collection;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2026-02-06T15:28:30+0000",
    comments = "version: 1.6.3, compiler: javac, environment: Java 21.0.4 (Azul Systems, Inc.)"
)
@Component
public class UserMapperImpl implements UserMapper {

    @Override
    public UserResponse createUserResponseFromUserEntity(UserEntity userEntity) {
        if ( userEntity == null ) {
            return null;
        }

        UserResponse.UserResponseBuilder userResponse = UserResponse.builder();

        Collection<RoleEntity> collection = userEntity.getRoles();
        if ( collection != null ) {
            userResponse.roles( new ArrayList<RoleEntity>( collection ) );
        }
        userResponse.id( userEntity.getId() );
        userResponse.uid( userEntity.getUid() );
        userResponse.name( userEntity.getName() );
        userResponse.username( userEntity.getUsername() );
        userResponse.lastname( userEntity.getLastname() );
        userResponse.firstname( userEntity.getFirstname() );
        userResponse.createdAt( userEntity.getCreatedAt() );

        return userResponse.build();
    }
}
