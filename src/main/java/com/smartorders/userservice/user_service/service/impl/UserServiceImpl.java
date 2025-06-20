package com.smartorders.userservice.user_service.service.impl;

import com.smartorders.userservice.user_service.dto.*;
import com.smartorders.userservice.user_service.exception.*;
import com.smartorders.userservice.user_service.mapper.UserMapper;
import com.smartorders.userservice.user_service.model.Role;
import com.smartorders.userservice.user_service.model.User;
import com.smartorders.userservice.user_service.repository.UserRepository;
import com.smartorders.userservice.user_service.repository.UserSpecification;
import com.smartorders.userservice.user_service.service.UserService;
import com.smartorders.userservice.user_service.service.jwt.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import static com.smartorders.userservice.user_service.util.EmailUtils.normalize;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final UserMapper userMapper;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public UserDto registerUser(RegisterRequest request) {
        if(request == null || request.getEmail() == null || request.getPassword() == null) {
            throw new InvalidUserDataException("Request cannot be null and must contain email and password");
        }

        String email = normalize(request.getEmail());
        Optional<User> foundUser = userRepository.findByEmail(email);

        if (foundUser.isPresent()){
            throw new UserAlreadyExistsException("User with email id " + request.getEmail() + " already exists in db");
        }

        User user = userMapper.toUser(request, encoder.encode(request.getPassword()));
        User savedUser = userRepository.save(user);
        return userMapper.toUserDto(savedUser);
    }

    @Override
    public JwtResponse loginUser(LoginRequest request) {
        
        if (request == null || request.getEmail() == null || request.getPassword() == null) {
            throw new InvalidUserDataException("Request cannot be null and must contain email and password");
        }
        // Normalize email
        String email = normalize(request.getEmail());

        // 🔐 Let Spring Security handle authentication (throws exception if invalid)
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, request.getPassword())
        );

        // ✅ Store the authentication in context (optional for token-based stateless APIs)
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 🔄 Get the authenticated user
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidCredentialsException("Email or Password is incorrect"));

        // 🔑 Generate JWT
        String token = jwtService.generateToken(user.getEmail());

        // 📦 Return user + token
        return new JwtResponse(userMapper.toUserDto(user), token);
    }

    @Override
    public UserDto getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            throw new UserNotAuthenticatedException("User is not authenticated");
        }
        String email = authentication.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        return userMapper.toUserDto(user);
    }

    @Override
    public UserDto updateProfile(UpdateProfileRequest request) {

        if (request == null || request.getEmail() == null || request.getName() == null) {
            throw new InvalidUserDataException("Request cannot be null and must contain email and name");
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            throw new UserNotAuthenticatedException("User is not authenticated");
        }
        String currentEmail = authentication.getName();
        if (!currentEmail.equals(request.getEmail())) {
            throw new UserNotAuthorizedException("You are not authorized to update this profile");
        }
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        user.setName(request.getName());
        // Add handling for more fields if needed
        User savedUser = userRepository.save(user);
        return userMapper.toUserDto(savedUser);
    }

    @Override
    public void changePassword(ChangePasswordRequest request) {
        
        if (request == null || request.getOldPassword() == null || request.getNewPassword() == null) {
            throw new InvalidUserDataException("Request cannot be null and must contain old and new passwords");
        }
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            throw new UserNotAuthenticatedException("User is not authenticated");
        }
        String email = authentication.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Verify old password
        if (!encoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new InvalidCredentialsException("Old password is incorrect");
        }

        // Update to new password
        user.setPassword(encoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    @Override
    public void logout(HttpServletRequest request) {
        // Clear the Spring Security context
        SecurityContextHolder.clearContext();
        // Optionally, invalidate the HTTP session if it exists
        if (request.getSession(false) != null) {
            request.getSession(false).invalidate();
        }
    }


    @Override
    public void changeUserRole(String email, String role) {
        User user = userRepository.findByEmail(normalize(email))
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Validate role
        if (!role.equalsIgnoreCase("USER") && !role.equalsIgnoreCase("ADMIN")) {
            throw new InvalidRoleException("Invalid role specified");
        }

        // Update role
        user.setRole(Role.valueOf(role.toUpperCase()));
        userRepository.save(user);
    }

    @Override
    public void removeUserRole(String email) {
        User user = userRepository.findByEmail(normalize(email))
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Remove role by setting it to USER
        user.setRole(Role.USER);
        userRepository.save(user);
    }

    @Override
    public List<UserDto> getUsersByRole(String role) {
        if (!role.equalsIgnoreCase("USER") && !role.equalsIgnoreCase("ADMIN")) {
            throw new InvalidRoleException("Invalid role specified");
        }

        List<User> users = userRepository.findByRole(Role.valueOf(role.toUpperCase()));

        return users.stream()
                .map(userMapper::toUserDto)
                .toList();
    }

    @Override
    public void deactivateCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            throw new UserNotAuthenticatedException("User is not authenticated");
        }
        String email = authentication.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Schedule account deactivation (e.g., using a background job or delayed task)
        user.setActive(false); // Assuming you have an 'active' field in User
        user.setDeactivatedAt(LocalDateTime.now());
        userRepository.save(user);
    }

    @Override
    public void deactivateUser(String email) {
        User user = userRepository.findByEmailAndActiveTrue(normalize(email))
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Schedule account deactivation (e.g., using a background job or delayed task)
        user.setActive(false); // Assuming you have an 'active' field in User
        user.setDeactivatedAt(LocalDateTime.now());
        userRepository.save(user);
    }

    @Override
    public void deleteUser(String email) {
        User user = userRepository.findByEmail(normalize(email))
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Delete the user permanently
        userRepository.delete(user);
    }

    @Override
    public void requestPasswordReset(String email) {
        User user = userRepository.findByEmail(normalize(email))
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Generate reset token and expiry
        String resetToken = jwtService.generateResetToken(user.getEmail());
        LocalDateTime resetTokenExpiry = LocalDateTime.now().plusHours(1); // Token valid for 1 hour

        // Update user with reset token and expiry
        user.setResetToken(resetToken);
        user.setResetTokenExpiry(resetTokenExpiry);
        userRepository.save(user);
    }

    @Override
    public void resetPassword(PasswordResetRequest request) {
        User user = userRepository.findByResetToken(request.getResetToken())
                .orElseThrow(() -> new InvalidResetTokenException("Invalid reset token"));

        // Check if token is expired
        if (user.getResetTokenExpiry() == null || user.getResetTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new InvalidResetTokenException("Reset token is expired");
        }

        // Update password
        user.setPassword(encoder.encode(request.getNewPassword()));
        user.setResetToken(null); // Clear reset token after use
        user.setResetTokenExpiry(null); // Clear expiry after use
        userRepository.save(user);
    }

    @Override
    public List<UserDto> searchUsers(UserSearchRequest request) {
        if (request == null) {
            throw new BadRequestException("Search request cannot be null");
        }
        Specification<User> specification = UserSpecification.build(request);

        return userRepository.findAll(specification)
                .stream()
                .map(userMapper::toUserDto)
                .toList();
    }
}