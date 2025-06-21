package com.smartorders.userservice.user_service.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateAddressRequest {
    private String street;
    private String city;
    private String postalCode;
    private String state;
    private String country;
    private Boolean isDefault;
}