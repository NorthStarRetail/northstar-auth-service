package com.northstar.northstar.auth.service.service;

import com.northstar.northstar.auth.service.dto.request.user.UserRequest;
import com.northstar.northstar.auth.service.dto.response.user.UserResponse;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface UserService {

    UserResponse createUser(UserRequest request);

    UserResponse getUserByUid(String uid);

    UserResponse getUserDetails(String username);

    List<UserResponse> getUsers(Pageable pageable);
}
