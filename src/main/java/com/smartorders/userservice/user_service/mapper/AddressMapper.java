package com.smartorders.userservice.user_service.mapper;

import com.smartorders.userservice.user_service.model.Address;
import org.springframework.stereotype.Component;
import com.smartorders.userservice.user_service.dto.AddressDto;
@Component
public class AddressMapper {

     public AddressDto toAddressDto(Address address) {
         return new AddressDto(
             address.getId(),
             address.getStreet(),
             address.getCity(),
             address.getPostalCode(),
             address.getState(),
             address.getCountry(),
             address.getIsDefault()
         );
     }
}
