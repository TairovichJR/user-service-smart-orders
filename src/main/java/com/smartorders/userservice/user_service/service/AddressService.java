package com.smartorders.userservice.user_service.service;

import com.smartorders.userservice.user_service.dto.AddressDto;
import com.smartorders.userservice.user_service.dto.AddAddressRequest;
import com.smartorders.userservice.user_service.dto.UpdateAddressRequest;

import java.util.List;

public interface AddressService {
    AddressDto addAddressForUser(AddAddressRequest request);
    AddressDto updateAddressForUser(Long addressId, UpdateAddressRequest request);
    void deleteAddressForUser(Long addressId);
    AddressDto getAddressById(Long addressId);
    List<AddressDto> getAllAddressesForUser();
    AddressDto addAddressForUserByAdmin(Long userId, AddAddressRequest request);
    AddressDto updateAddressForUserByAdmin(Long userId, Long addressId, UpdateAddressRequest request);
    void deleteAddressForUserByAdmin(Long userId, Long addressId);
    AddressDto getAddressByIdForUserByAdmin(Long userId, Long addressId);
    List<AddressDto> getAllAddressesForUserByAdmin(Long userId);
}
