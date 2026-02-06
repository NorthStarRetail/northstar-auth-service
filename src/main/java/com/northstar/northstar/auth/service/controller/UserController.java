package com.northstar.northstar.auth.service.controller;

import com.northstar.northstar.auth.service.dto.response.user.UserResponse;
import com.northstar.northstar.auth.service.service.UserService;
import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/users")
@Tag(name = "Users", description = "User Management API")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @Hidden
    @GetMapping("/ping")
    public String ping(Authentication authentication) {
        return "Hello " + authentication.getName();
    }

    @Operation(summary = "Get all users", description = "Returns all users", tags = {"Users"})
    @GetMapping
    public ResponseEntity<List<UserResponse>> getUsers(
            @Parameter(description = "Page number (default: 0)") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size (default: 10)") @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(userService.getUsers(PageRequest.of(page, size)));
    }

    @Operation(summary = "Get current user details", description = "Returns current user details", tags = {"Users"})
    @GetMapping("/details")
    public ResponseEntity<UserResponse> getUserDetails(Authentication authentication) {
        return ResponseEntity.ok(userService.getUserDetails(authentication.getName()));
    }

    @Operation(summary = "Get user by ID", description = "Returns user details by uid", tags = {"Users"})
    @GetMapping("/{id}")
    public ResponseEntity<UserResponse> getUser(@PathVariable String id) {
        return ResponseEntity.ok(userService.getUserByUid(id));
    }
}
