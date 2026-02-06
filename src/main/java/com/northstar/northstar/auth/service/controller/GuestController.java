package com.northstar.northstar.auth.service.controller;

import com.northstar.northstar.auth.service.dto.request.user.UserRequest;
import com.northstar.northstar.auth.service.dto.response.user.UserResponse;
import com.northstar.northstar.auth.service.enums.RoleEnums;
import com.northstar.northstar.auth.service.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/guests")
@Tag(name = "Guest Access", description = "Public registration endpoints")
public class GuestController {

    private final UserService userService;

    public GuestController(UserService userService) {
        this.userService = userService;
    }

    @Operation(summary = "Create user", description = "Register a new user", tags = {"Guest Access"})
    @PostMapping("/user")
    public ResponseEntity<UserResponse> createUser(@RequestBody @Valid UserRequest userRequest) {
        userRequest.setRole(RoleEnums.User);
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(userRequest));
    }

    @Operation(summary = "Create admin", description = "Register a new admin", tags = {"Guest Access"})
    @PostMapping("/admin")
    public ResponseEntity<UserResponse> createAdmin(@RequestBody @Valid UserRequest userRequest) {
        userRequest.setRole(RoleEnums.Admin);
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(userRequest));
    }
}
