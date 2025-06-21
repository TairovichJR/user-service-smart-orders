package com.smartorders.userservice.user_service.dto;

import jakarta.validation.constraints.Email;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
public class UpdateProfileRequest {

    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String profileImageUrl;
    private LocalDate dateOfBirth;
}