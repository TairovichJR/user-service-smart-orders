package com.smartorders.userservice.user_service.mapper;

import com.smartorders.userservice.user_service.dto.RegisterRequest;
import com.smartorders.userservice.user_service.dto.UserDto;
import com.smartorders.userservice.user_service.dto.AddressDto;
import com.smartorders.userservice.user_service.model.Role;
import com.smartorders.userservice.user_service.model.User;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

import static com.smartorders.userservice.user_service.util.EmailUtils.normalize;

@Component
public class UserMapper {

    private final AddressMapper addressMapper;

    public UserMapper(AddressMapper addressMapper) {
        this.addressMapper = addressMapper;
    }

    public UserDto toUserDto(User user) {
        List<AddressDto> addressDtos = user.getAddresses() != null
                ? user.getAddresses().stream()
                .map(addressMapper::toAddressDto)
                .collect(Collectors.toList())
                : null;

        return UserDto.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phoneNumber(user.getPhoneNumber())
                .profileImageUrl(user.getProfileImageUrl())
                .dateOfBirth(user.getDateOfBirth())
                .createdAt(user.getCreatedAt() != null ? user.getCreatedAt().toString() : null)
                .updatedAt(user.getUpdatedAt() != null ? user.getUpdatedAt().toString() : null)
                .lastLoginAt(user.getLastLoginAt() != null ? user.getLastLoginAt().toString() : null)
                .email(user.getEmail())
                .role(user.getRole().name())
                .deactivatedAt(user.getDeactivatedAt())
                .addresses(addressDtos)
                .build();
    }

    public User toUser(RegisterRequest request, String encodedPassword) {
        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(normalize(request.getEmail().trim().toLowerCase()));
        user.setPassword(encodedPassword);
        user.setRole(Role.USER);
        return user;
    }
}