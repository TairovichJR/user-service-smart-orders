package com.smartorders.userservice.user_service;

import com.smartorders.userservice.user_service.model.Address;
import com.smartorders.userservice.user_service.model.Role;
import com.smartorders.userservice.user_service.model.User;
import com.smartorders.userservice.user_service.repository.AddressRepository;
import com.smartorders.userservice.user_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.password.PasswordEncoder;


@SpringBootApplication
@RequiredArgsConstructor
@EnableScheduling
public class UserServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserServiceApplication.class, args);
	}

	@Bean
	public CommandLineRunner createDefaultUsersAndAddresses(
			UserRepository userRepository,
			AddressRepository addressRepository,
			PasswordEncoder passwordEncoder
	) {
		return args -> {
			// Admins
			String[] adminEmails = {"admin1@admin.com", "admin2@admin.com"};
			for (int i = 0; i < adminEmails.length; i++) {
				String adminEmail = adminEmails[i];
				if (userRepository.findByEmail(adminEmail).isEmpty()) {
					User admin = new User();
					admin.setEmail(adminEmail);
					admin.setPassword(passwordEncoder.encode("admin123"));
					admin.setRole(Role.ADMIN);
					admin.setFirstName("AdminFirstName " + (i + 1));
					admin.setLastName("AdminLastName " + (i + 1));
					admin.setActive(true);
					User savedAdmin = userRepository.save(admin);

					Address adminAddress = new Address();
					adminAddress.setUser(savedAdmin);
					adminAddress.setStreet("Admin Street " + (i + 1));
					adminAddress.setCity("Admin City");
					adminAddress.setState("Admin State");
					adminAddress.setPostalCode("0000" + (i + 1));
					adminAddress.setCountry("Adminland");
					adminAddress.setIsDefault(true);
					addressRepository.save(adminAddress);
				}
			}
			// Users
			for (int i = 1; i <= 20; i++) {
				String userEmail = "user" + i + "@user.com";
				if (userRepository.findByEmail(userEmail).isEmpty()) {
					User user = new User();
					user.setEmail(userEmail);
					user.setPassword(passwordEncoder.encode("user123"));
					user.setRole(Role.USER);
					user.setFirstName("UserFirstName " + i);
					user.setLastName("UserLastName " + i);
					user.setActive(true);
					User savedUser = userRepository.save(user);

					Address userAddress = new Address();
					userAddress.setUser(savedUser);
					userAddress.setStreet("User Street " + i);
					userAddress.setCity("User City");
					userAddress.setState("User State");
					userAddress.setPostalCode("1000" + i);
					userAddress.setCountry("Userland");
					userAddress.setIsDefault(true);
					addressRepository.save(userAddress);
				}
			}
		};
	}
}
