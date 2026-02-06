package com.northstar.northstar.auth.service.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.UUID;

@Entity
@Table(name = "ns_users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, updatable = false, length = 36)
    private String uid;

    @NotBlank
    @Column(unique = true)
    private String username;

    @NotBlank
    private String lastname;

    @NotBlank
    private String firstname;

    @NotBlank
    private String password;

    @Builder.Default
    private boolean enabled = true;

    @Builder.Default
    private boolean accountNonLocked = true;

    @Builder.Default
    private boolean accountNonExpired = true;

    @Builder.Default
    private boolean credentialsNonExpired = true;

    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<RoleEntity> roles;

    @NotNull
    private LocalDateTime createdAt;

    @Transient
    private String name;

    public String getName() {
        return String.format("%s %s", getLastname(), getFirstname());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .toList();
    }

    @PrePersist
    private void generateUid() {
        if (uid == null) {
            uid = UUID.randomUUID().toString();
        }
    }
}
