package com.smartorders.userservice.user_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@AllArgsConstructor
@Builder
public class AuthUserDto {
    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private String role;
    private String token;
}
