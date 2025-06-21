package com.smartorders.userservice.user_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@AllArgsConstructor
@Builder
public class UserDto {
    private Long id;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String profileImageUrl;
    private LocalDate dateOfBirth;
    private String createdAt;
    private String updatedAt;
    private String lastLoginAt;
    private String email;
    private String role;
    private LocalDateTime deactivatedAt;
    private List<AddressDto> addresses;
}
