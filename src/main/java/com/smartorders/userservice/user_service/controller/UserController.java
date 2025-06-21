package com.smartorders.userservice.user_service.controller;

import com.smartorders.userservice.user_service.dto.*;
import com.smartorders.userservice.user_service.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<UserDto> register(@RequestBody @Valid RegisterRequest request){
       return ResponseEntity.status(HttpStatus.CREATED).body(userService.registerUser(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthUserDto> login(@RequestBody @Valid LoginRequest request){
        return ResponseEntity.status(HttpStatus.OK).body(userService.loginUser(request));
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @GetMapping("/profile")
    public ResponseEntity<UserDto> getCurrentUser() {
        UserDto userDto = userService.getCurrentUser();
        return ResponseEntity.ok(userDto);
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @PutMapping("/profile")
    public ResponseEntity<UserDto> updateProfile(@RequestBody @Valid UpdateProfileRequest request) {
        UserDto updatedUser = userService.updateProfile(request);
        return ResponseEntity.ok(updatedUser);
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(@RequestBody @Valid ChangePasswordRequest request) {
        userService.changePassword(request);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request){
        userService.logout(request);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/users/{userId}/role")
    public ResponseEntity<Void> changeUserRole(@PathVariable Long userId, @RequestParam String role) {
        userService.changeUserRole(userId, role);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{userId}/role")
    public ResponseEntity<Void> removeUserRole(@PathVariable Long userId) {
        userService.removeUserRole(userId);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users/role/{role}")
    public ResponseEntity<List<UserDto>> getUsersByRole(@PathVariable String role) {
        List<UserDto> users = userService.getUsersByRole(role);
        return ResponseEntity.ok(users);
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @DeleteMapping("/deactivate")
    public ResponseEntity<String> deactivateAccount(){
        userService.deactivateCurrentUser();
        return ResponseEntity.ok("Your account is scheduled for deletion after 5 minutes. You can recover it before then");
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{userId}/deactivate")
    public ResponseEntity<String> deactivateUser(@PathVariable Long userId) {
        userService.deactivateUser(userId);
        return ResponseEntity.ok("User account is scheduled for deletion after 5 minutes. It can be recovered before then.");
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{userId}/delete")
    public ResponseEntity<String> deleteUser(@PathVariable Long userId) {
        userService.deleteUser(userId);
        return ResponseEntity.ok("User account has been permanently deleted.");
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @PostMapping("/request-password-reset")
    public ResponseEntity<Void> requestPasswordReset() {
        userService.requestPasswordReset();
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(@RequestBody @Valid PasswordResetRequest request) {
        userService.resetPassword(request);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/users/search")
    public ResponseEntity<List<UserDto>> searchUsers(@RequestBody @Valid UserSearchRequest request) {
        List<UserDto> users = userService.searchUsers(request);
        return ResponseEntity.ok(users);
    }

}