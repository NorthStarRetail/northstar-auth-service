package com.northstar.northstar.auth.service.dto.response.user;

import com.northstar.northstar.auth.service.entity.RoleEntity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Collection;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponse {

    private Long id;
    private String uid;
    private String name;
    private String username;
    private String lastname;
    private String firstname;
    private Collection<RoleEntity> roles;
    private LocalDateTime createdAt;
}
