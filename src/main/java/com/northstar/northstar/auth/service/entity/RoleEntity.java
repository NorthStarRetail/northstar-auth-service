package com.northstar.northstar.auth.service.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;

@Entity
@Table(name = "ns_roles")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RoleEntity implements GrantedAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String name;

    private String description;

    @Override
    public String getAuthority() {
        return name;
    }
}
