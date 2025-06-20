package com.smartorders.userservice.user_service.mapper;

import com.smartorders.userservice.user_service.dto.RegisterRequest;
import com.smartorders.userservice.user_service.dto.UserDto;
import com.smartorders.userservice.user_service.model.Role;
import com.smartorders.userservice.user_service.model.User;
import org.springframework.stereotype.Component;
import static com.smartorders.userservice.user_service.util.EmailUtils.normalize;

@Component
public class UserMapper {

    public UserDto toUserDto(User user){
        return UserDto.builder()
                .id(user.getId())
                .role(user.getRole().name())
                .name(user.getName())
                .email(user.getEmail())
                .build();
    }

    public User toUser(RegisterRequest request, String encodedPassword){
        User user = new User();
        user.setName(request.getName());
        user.setEmail(normalize(request.getEmail().trim().toLowerCase()));
        user.setPassword(encodedPassword);
        user.setRole(Role.USER);
        return user;
    }
}
