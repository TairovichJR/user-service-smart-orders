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
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<UserDto> register(@RequestBody @Valid RegisterRequest request){
       return ResponseEntity.status(HttpStatus.CREATED).body(userService.registerUser(request));
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody @Valid LoginRequest request){
        return ResponseEntity.status(HttpStatus.OK).body(userService.loginUser(request));
    }

    @GetMapping("/profile")
    public ResponseEntity<UserDto> getCurrentUser() {
        UserDto userDto = userService.getCurrentUser();
        return ResponseEntity.ok(userDto);
    }

    @PutMapping("/profile")
    public ResponseEntity<UserDto> updateProfile(@RequestBody @Valid UpdateProfileRequest request) {
        UserDto updatedUser = userService.updateProfile(request);
        return ResponseEntity.ok(updatedUser);
    }

    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(@RequestBody @Valid ChangePasswordRequest request) {
        userService.changePassword(request);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request){
        userService.logout(request);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/users/{email}/role")
    public ResponseEntity<Void> changeUserRole(@PathVariable String email, @RequestParam String role) {
        userService.changeUserRole(email, role);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{email}/role")
    public ResponseEntity<Void> removeUserRole(@PathVariable String email) {
        userService.removeUserRole(email);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users/role/{role}")
    public ResponseEntity<List<UserDto>> getUsersByRole(@PathVariable String role) {
        List<UserDto> users = userService.getUsersByRole(role);
        return ResponseEntity.ok(users);
    }

    @DeleteMapping("deactivate")
    public ResponseEntity<String> deactivateAccount(){
        userService.deactivateCurrentUser();
        return ResponseEntity.ok("Your account is scheduled for deletion after 5 minutes. You can recover it before then");
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{email}/deactivate")
    public ResponseEntity<String> deactivateUser(@PathVariable String email) {
        userService.deactivateUser(email);
        return ResponseEntity.ok("User account is scheduled for deletion after 5 minutes. It can be recovered before then.");
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{email}/delete")
    public ResponseEntity<String> deleteUser(@PathVariable String email) {
        userService.deleteUser(email);
        return ResponseEntity.ok("User account has been permanently deleted.");
    }

    @PostMapping("/request-password-reset")
    public ResponseEntity<Void> requestPasswordReset(@RequestParam @Valid String email) {
        userService.requestPasswordReset(email);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(@RequestBody @Valid PasswordResetRequest request) {
        userService.resetPassword(request);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/users/search")
    public ResponseEntity<List<UserDto>> searchUsers(@RequestBody @Valid UserSearchRequest request) {
        // Validate userId (must be positive if present)
        if (request.getUserId() != null && request.getUserId() < 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid userId value: " + request.getUserId());
        }
        // Validate name (optional: non-empty, no special chars, etc.)
        if (request.getName() != null && request.getName().trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Name cannot be empty");
        }
        // Validate email (simple regex)
        if (request.getEmail() != null && !request.getEmail().matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid email format: " + request.getEmail());
        }
        // Validate role (must be ADMIN or USER if present)
        if (request.getRole() != null &&
                !request.getRole().equals("ADMIN") &&
                !request.getRole().equals("USER")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid role value: " + request.getRole());
        }
        // Validate isActive (no validation needed for Boolean, but you can check for null if required)
        List<UserDto> users = userService.searchUsers(request);
        return ResponseEntity.ok(users);
    }

}