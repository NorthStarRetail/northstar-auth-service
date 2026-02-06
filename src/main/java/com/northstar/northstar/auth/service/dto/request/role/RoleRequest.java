package com.northstar.northstar.auth.service.dto.request.role;

import com.northstar.northstar.auth.service.enums.RoleEnums;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class RoleRequest {
    private RoleEnums role;
}
