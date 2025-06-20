package com.smartorders.userservice.user_service.service;

import com.smartorders.userservice.user_service.dto.*;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

public interface UserService {
    UserDto registerUser(RegisterRequest request);
    JwtResponse loginUser(LoginRequest request);
    UserDto getCurrentUser();
    UserDto updateProfile(UpdateProfileRequest request);
    void changePassword(ChangePasswordRequest request);
    void logout(HttpServletRequest request);
    void changeUserRole(String email, String role);
    void removeUserRole(String email);
    List<UserDto> getUsersByRole(String role);
    void deactivateCurrentUser();
    void deactivateUser(String email);
    void deleteUser(String email);
    void requestPasswordReset(String email);
    void resetPassword(PasswordResetRequest request);
    List<UserDto> searchUsers(UserSearchRequest request);
}
