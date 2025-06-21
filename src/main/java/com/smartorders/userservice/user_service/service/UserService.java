package com.smartorders.userservice.user_service.service;

import com.smartorders.userservice.user_service.dto.*;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

public interface UserService {
    UserDto registerUser(RegisterRequest request);
    AuthUserDto loginUser(LoginRequest request);
    UserDto getCurrentUser();
    UserDto updateProfile(UpdateProfileRequest request);
    void changePassword(ChangePasswordRequest request);
    void logout(HttpServletRequest request);
    void changeUserRole(Long userId, String role);
    void removeUserRole(Long userId);
    List<UserDto> getUsersByRole(String role);
    void deactivateCurrentUser();
    void deactivateUser(Long userId);
    void deleteUser(Long userId);
    void requestPasswordReset();
    void resetPassword(PasswordResetRequest request);
    List<UserDto> searchUsers(UserSearchRequest request);
}
