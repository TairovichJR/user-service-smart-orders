package com.smartorders.userservice.user_service;

import com.smartorders.userservice.user_service.model.Role;
import com.smartorders.userservice.user_service.model.User;
import com.smartorders.userservice.user_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;

@SpringBootApplication
@RequiredArgsConstructor
@EnableScheduling
public class UserServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserServiceApplication.class, args);
	}


	@Bean
	public CommandLineRunner createDefaultUsers(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		return args -> {
			// Admins
			String[] adminEmails = {"admin1@admin.com", "admin2@admin.com"};
			for (String adminEmail : adminEmails) {
				if (userRepository.findByEmail(adminEmail).isEmpty()) {
					User admin = new User();
					admin.setEmail(adminEmail);
					admin.setPassword(passwordEncoder.encode("admin123")); // Change password as needed
					admin.setRole(Role.ADMIN);
					admin.setName("Admin " + adminEmail.split("@")[0]);
					userRepository.save(admin);
				}
			}
			// Users
			for (int i = 1; i <= 500; i++) {
				String userEmail = "user" + i + "@user.com";
				if (userRepository.findByEmail(userEmail).isEmpty()) {
					User user = new User();
					user.setEmail(userEmail);
					user.setPassword(passwordEncoder.encode("user123")); // Change password as needed
					user.setRole(Role.USER);
					user.setName("User " + i);
					if (i % 2 == 0) {
						user.setActive(false); // Deactivate every second user
						user.setDeactivatedAt(LocalDateTime.now());
					} else {
						user.setActive(true);
					}
					userRepository.save(user);
				}
			}
		};
	}
}
