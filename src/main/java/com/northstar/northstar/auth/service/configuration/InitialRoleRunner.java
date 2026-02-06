package com.northstar.northstar.auth.service.configuration;

import com.northstar.northstar.auth.service.entity.RoleEntity;
import com.northstar.northstar.auth.service.enums.RoleEnums;
import com.northstar.northstar.auth.service.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Component
@RequiredArgsConstructor
@Slf4j
public class InitialRoleRunner implements ApplicationRunner {

    private final RoleRepository roleRepository;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        for (RoleEnums roleEnum : RoleEnums.values()) {
            String name = roleEnum.getValue();
            if (roleRepository.findByName(name).isEmpty()) {
                RoleEntity role = Objects.requireNonNull(RoleEntity.builder()
                        .name(name)
                        .description(roleEnum.name())
                        .build());
                roleRepository.save(role);
                log.info("Created role: {}", name);
            }
        }
    }
}
