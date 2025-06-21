package com.smartorders.userservice.user_service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class UserSearchRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String role;
    private Boolean isActive;
}
