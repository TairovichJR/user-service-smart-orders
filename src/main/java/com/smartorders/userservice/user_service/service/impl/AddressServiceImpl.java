package com.smartorders.userservice.user_service.service.impl;

import com.smartorders.userservice.user_service.dto.AddressDto;
import com.smartorders.userservice.user_service.dto.AddAddressRequest;
import com.smartorders.userservice.user_service.dto.UpdateAddressRequest;
import com.smartorders.userservice.user_service.exception.InvalidUserDataException;
import com.smartorders.userservice.user_service.exception.UserNotAuthenticatedException;
import com.smartorders.userservice.user_service.exception.UserNotFoundException;
import com.smartorders.userservice.user_service.model.Address;
import com.smartorders.userservice.user_service.model.User;
import com.smartorders.userservice.user_service.repository.AddressRepository;
import com.smartorders.userservice.user_service.repository.UserRepository;
import com.smartorders.userservice.user_service.service.AddressService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class AddressServiceImpl implements AddressService {

    private final UserRepository userRepository;
    private final AddressRepository addressRepository;

    @Override
     public AddressDto addAddressForUser(AddAddressRequest request) {
         validateAddressRequest(request);
         User user = getAuthenticatedUser();
         return addAddressToUser(user, request);
     }

     @Override
     public AddressDto addAddressForUserByAdmin(Long userId, AddAddressRequest request) {
         validateAddressRequest(request);
         User user = userRepository.findById(userId)
                 .orElseThrow(() -> new UserNotFoundException("User not found"));
         return addAddressToUser(user, request);
     }

     private AddressDto addAddressToUser(User user, AddAddressRequest request) {
         Address address = Address.builder()
                 .street(request.getStreet())
                 .city(request.getCity())
                 .postalCode(request.getPostalCode())
                 .state(request.getState())
                 .country(request.getCountry())
                 .isDefault(request.getIsDefault())
                 .user(user)
                 .build();

         user.getAddresses().add(address);

         if (address.getIsDefault()) {
             user.getAddresses().stream()
                     .filter(a -> a != address)
                     .forEach(a -> a.setIsDefault(false));
         }

         Address savedAddress = addressRepository.save(address);
         userRepository.save(user);

         return mapToDto(savedAddress);
     }
    @Override
    public AddressDto updateAddressForUser(Long addressId, UpdateAddressRequest request) {

        if (request == null) {
            throw new InvalidUserDataException("Request cannot be null");
        }

        User user = getAuthenticatedUser();

        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new InvalidUserDataException("Address not found"));

        // Ensure the address belongs to the user
        if (!address.getUser().getId().equals(user.getId())) {
            throw new InvalidUserDataException("Address does not belong to the user");
        }

        // Update fields
        address.setStreet(request.getStreet() != null ? request.getStreet() : address.getStreet());
        address.setCity(request.getCity() != null ? request.getCity() : address.getCity());
        address.setPostalCode(request.getPostalCode() != null ? request.getPostalCode() : address.getPostalCode());
        address.setState(request.getState() != null ? request.getState() : address.getState());
        address.setCountry(request.getCountry() != null ? request.getCountry() : address.getCountry());

        Boolean isDefault = request.getIsDefault();
        Boolean wasDefault = address.getIsDefault();

        if (isDefault != null) {
            address.setIsDefault(isDefault);

            // Handle default address logic
            if (isDefault && !Boolean.TRUE.equals(wasDefault)) {
                user.getAddresses().stream()
                        .filter(a -> !a.getId().equals(address.getId()))
                        .forEach(a -> a.setIsDefault(false));
            }
        }

        Address updatedAddress = addressRepository.save(address);
        return mapToDto(updatedAddress);
    }

    @Override
    public void deleteAddressForUser(Long addressId) {
        User user = getAuthenticatedUser();

        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new InvalidUserDataException("Address not found"));

        if (!address.getUser().getId().equals(user.getId())) {
            throw new InvalidUserDataException("Address does not belong to the user");
        }

        boolean wasDefault = address.getIsDefault();
        addressRepository.delete(address);

        if (wasDefault) {
            List<Address> remaining = addressRepository.findByUserId(user.getId());
            if (!remaining.isEmpty()) {
                Address newDefault = remaining.getFirst();
                newDefault.setIsDefault(true);
                addressRepository.save(newDefault);
            }
        }
    }

    @Override
    public AddressDto getAddressById(Long addressId) {
        User user = getAuthenticatedUser();
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new InvalidUserDataException("Address not found"));
        if (!address.getUser().getId().equals(user.getId())) {
            throw new InvalidUserDataException("Address does not belong to the user");
        }
        return mapToDto(address);
    }

    @Override
    public List<AddressDto> getAllAddressesForUser() {
        User user = getAuthenticatedUser();
        List<Address> addresses = addressRepository.findByUserId(user.getId());
        if (addresses != null && !addresses.isEmpty()) {
            return addresses.stream()
                    .map(this::mapToDto)
                    .toList();
        }
        return List.of();
    }

    @Override
    public AddressDto updateAddressForUserByAdmin(Long userId, Long addressId, UpdateAddressRequest request) {
        if (request == null) {
            throw new InvalidUserDataException("Request cannot be null");
        }
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new InvalidUserDataException("Address not found"));
        if (!address.getUser().getId().equals(user.getId())) {
            throw new InvalidUserDataException("Address does not belong to the user");
        }
        address.setStreet(request.getStreet() != null ? request.getStreet() : address.getStreet());
        address.setCity(request.getCity() != null ? request.getCity() : address.getCity());
        address.setPostalCode(request.getPostalCode() != null ? request.getPostalCode() : address.getPostalCode());
        address.setState(request.getState() != null ? request.getState() : address.getState());
        address.setCountry(request.getCountry() != null ? request.getCountry() : address.getCountry());
        Boolean isDefault = request.getIsDefault();
        Boolean wasDefault = address.getIsDefault();
        if (isDefault != null) {
            address.setIsDefault(isDefault);
            if (isDefault && !Boolean.TRUE.equals(wasDefault)) {
                user.getAddresses().stream()
                        .filter(a -> !a.getId().equals(address.getId()))
                        .forEach(a -> a.setIsDefault(false));
            }
        }
        Address updatedAddress = addressRepository.save(address);
        return mapToDto(updatedAddress);
    }

    @Override
    public void deleteAddressForUserByAdmin(Long userId, Long addressId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new InvalidUserDataException("Address not found"));
        if (!address.getUser().getId().equals(user.getId())) {
            throw new InvalidUserDataException("Address does not belong to the user");
        }
        boolean wasDefault = address.getIsDefault();
        addressRepository.delete(address);
        if (wasDefault) {
            List<Address> remaining = addressRepository.findByUserId(user.getId());
            if (!remaining.isEmpty()) {
                Address newDefault = remaining.getFirst();
                newDefault.setIsDefault(true);
                addressRepository.save(newDefault);
            }
        }
    }

    @Override
    public AddressDto getAddressByIdForUserByAdmin(Long userId, Long addressId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new InvalidUserDataException("Address not found"));
        if (!address.getUser().getId().equals(user.getId())) {
            throw new InvalidUserDataException("Address does not belong to the user");
        }
        return mapToDto(address);
    }

    @Override
    public List<AddressDto> getAllAddressesForUserByAdmin(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        List<Address> addresses = addressRepository.findByUserId(user.getId());
        if (addresses != null && !addresses.isEmpty()) {
            return addresses.stream()
                    .map(this::mapToDto)
                    .toList();
        }
        return List.of();
    }

    private User getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            throw new UserNotAuthenticatedException("User is not authenticated");
        }
        String currentEmail = authentication.getName();
        return userRepository.findByEmail(currentEmail)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
    }

    private void validateAddressRequest(AddAddressRequest request) {
        if (request == null) {
            throw new InvalidUserDataException("Request cannot be null");
        }
        if (request.getStreet() == null || request.getStreet().isBlank()) {
            throw new InvalidUserDataException("Street cannot be empty");
        }
        if (request.getCity() == null || request.getCity().isBlank()) {
            throw new InvalidUserDataException("City cannot be empty");
        }
        if (request.getPostalCode() == null || request.getPostalCode().isBlank()) {
            throw new InvalidUserDataException("Postal code cannot be empty");
        }
        if (request.getCountry() == null || request.getCountry().isBlank()) {
            throw new InvalidUserDataException("Country cannot be empty");
        }
        if (request.getState() == null || request.getState().isBlank()) {
            throw new InvalidUserDataException("State cannot be empty");
        }
        if (request.getIsDefault() == null) {
            throw new InvalidUserDataException("Default address flag cannot be null");
        }
    }

    private AddressDto mapToDto(Address address) {
        return AddressDto.builder()
                .id(address.getId())
                .street(address.getStreet())
                .city(address.getCity())
                .postalCode(address.getPostalCode())
                .state(address.getState())
                .country(address.getCountry())
                .isDefault(address.getIsDefault())
                .build();
    }
}