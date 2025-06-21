package com.smartorders.userservice.user_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@AllArgsConstructor
@Builder
public class AddressDto {
    private Long id;
    private String street;
    private String city;
    private String postalCode;
    private String state;
    private String country;
    private boolean isDefault;
}