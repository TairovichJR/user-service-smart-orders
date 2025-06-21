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
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import java.time.LocalDateTime;
import java.util.List;
import static com.smartorders.userservice.user_service.util.EmailUtils.normalize;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private static final long AUTH_TOKEN_EXPIRATION_MS = 1000 * 60 * 60 * 24; // 24 hours
    private static final long PASSWORD_RESET_TOKEN_EXPIRATION_MS = 1000 * 60 * 30; // 30 mins

    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final UserMapper userMapper;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public UserDto registerUser(RegisterRequest request) {

        String email = normalize(request.getEmail());

        userRepository.findByEmail(email)
                .ifPresent(user -> {
                    throw new UserAlreadyExistsException("User with email id " + request.getEmail() + " already exists in db");
                });

        User user = userMapper.toUser(request, encoder.encode(request.getPassword()));
        User savedUser = userRepository.save(user);
        return userMapper.toUserDto(savedUser);
    }

    @Override
    public AuthUserDto loginUser(LoginRequest request) {

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
        String token = jwtService.generateToken(user.getEmail(), AUTH_TOKEN_EXPIRATION_MS);

        return AuthUserDto.builder()
                .email(user.getEmail())
                .role(user.getRole().name())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .id(user.getId())
                .token(token)
                .build();
    }

    @Override
    public UserDto getCurrentUser() {
        return userMapper.toUserDto(getAuthenticatedUser());
    }

    @Override
    public UserDto updateProfile(UpdateProfileRequest request) {

        if (request == null) {
            throw new InvalidUserDataException("Request cannot be null");
        }

        User user = getAuthenticatedUser();

        if (request.getFirstName() != null) user.setFirstName(request.getFirstName());
        if (request.getLastName() != null) user.setLastName(request.getLastName());
        if (request.getPhoneNumber() != null) user.setPhoneNumber(request.getPhoneNumber());
        if (request.getProfileImageUrl() != null) user.setProfileImageUrl(request.getProfileImageUrl());
        if (request.getDateOfBirth() != null) user.setDateOfBirth(request.getDateOfBirth());

        User savedUser = userRepository.save(user);
        return userMapper.toUserDto(savedUser);
    }

    @Transactional
    @Override
    public void changePassword(ChangePasswordRequest request) {
        
        if (request == null || request.getOldPassword() == null || request.getNewPassword() == null) {
            throw new InvalidUserDataException("Request cannot be null and must contain old and new passwords");
        }

        User user = getAuthenticatedUser();

        if (!encoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new InvalidCredentialsException("Old password is incorrect");
        }

        user.setPassword(encoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    @Override
    public void logout(HttpServletRequest request) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            throw new UserNotAuthenticatedException("You must be authenticated to log out.");
        }

        SecurityContextHolder.clearContext();
        if (request.getSession(false) != null) {
            request.getSession(false).invalidate();
        }
    }


    @Override
    public void changeUserRole(Long userId, String role) {
        validateUserId(userId);
        validateRole(role);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        user.setRole(Role.valueOf(role.toUpperCase()));
        userRepository.save(user);
    }

    private void validateRole(String role) {
        if (role == null || (!role.equalsIgnoreCase(Role.USER.name()) && !role.equalsIgnoreCase(Role.ADMIN.name()))) {
            throw new InvalidRoleException("Invalid role specified");
        }
    }

    @Override
    public void removeUserRole(Long userId) {
        validateUserId(userId);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        user.setRole(Role.USER);
        userRepository.save(user);
    }

    @Override
    public List<UserDto> getUsersByRole(String role) {
        validateRole(role);
        List<User> users = userRepository.findByRole(Role.valueOf(role.toUpperCase()));
        return users.stream()
                .map(userMapper::toUserDto)
                .toList();
    }

    @Transactional
    @Override
    public void deactivateCurrentUser() {
        User user = getAuthenticatedUser();

        deactivateUser(user);
    }

    @Transactional
    @Override
    public void deactivateUser(Long userId) {
        validateUserId(userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        deactivateUser(user);
    }

    private void deactivateUser(User user) {
        if (!user.isActive()) {
            throw new UserNotActiveException("User account is already inactive");
        }
        user.setActive(false);
        user.setDeactivatedAt(LocalDateTime.now());
        userRepository.save(user);
    }

    @Transactional
    @Override
    public void deleteUser(Long userId) {
        validateUserId(userId);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        userRepository.delete(user);
    }

    @Override
    public void requestPasswordReset() {
        User user = getAuthenticatedUser();
        if (!user.isActive()){
            throw new UserNotActiveException("User account is not active");
        }

        String resetToken = jwtService.generateToken(user.getEmail(), PASSWORD_RESET_TOKEN_EXPIRATION_MS);
        user.setResetToken(resetToken);
        userRepository.save(user);
    }

    @Override
    public void resetPassword(PasswordResetRequest request) {

        if (request == null || request.getResetToken() == null || request.getNewPassword() == null) {
            throw new InvalidUserDataException("Request cannot be null and must contain reset token and new password");
        }

        User user = userRepository.findByResetToken(request.getResetToken())
                .orElseThrow(() -> new InvalidResetTokenException("Invalid reset token"));

        if (!user.isActive()){
            throw new UserNotActiveException("User account is not active");
        }

        if (user.getResetToken() == null || !user.getResetToken().equals(request.getResetToken())) {
            throw new InvalidResetTokenException("Reset token has already been used or is invalid");
        }

        if(!jwtService.isTokenValid(request.getResetToken(), user.getEmail())) {
            throw new InvalidResetTokenException("Reset token is invalid");
        }
        user.setPassword(encoder.encode(request.getNewPassword()));
        user.setResetToken(null);
        userRepository.save(user);
    }

    @Override
    public List<UserDto> searchUsers(UserSearchRequest request) {
        if (request == null) {
            throw new BadRequestException("Search request cannot be null");
        }

        if (request.getFirstName() != null && request.getFirstName().trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Name cannot be empty");
        }
        if (request.getLastName() != null && request.getLastName().trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Last name cannot be empty");
        }

        if (request.getEmail() != null && !request.getEmail().matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid email format: " + request.getEmail());
        }
        if (request.getRole() != null &&
                !request.getRole().equals(Role.ADMIN.name()) &&
                !request.getRole().equals(Role.USER.name())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid role value: " + request.getRole());
        }

        Specification<User> specification = UserSpecification.build(request);

        return userRepository.findAll(specification)
                .stream()
                .map(userMapper::toUserDto)
                .toList();
    }

    private User getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            throw new UserNotAuthenticatedException("User is not authenticated");
        }
        String email = authentication.getName();
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
    }

    private void validateUserId(Long userId) {
        if (userId == null || userId <= 0) {
            throw new InvalidUserDataException("User Id must be a positive number");
        }
    }
}