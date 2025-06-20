package com.smartorders.userservice.user_service.service;

import com.smartorders.userservice.user_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class UserCleanUpService {

    private final UserRepository userRepository;

    @Scheduled(fixedRate = 30000)
    public void deleteExpiredDeactivatedUsers(){
        System.out.println("Running scheduled cleanup of deactivated users...");
        LocalDateTime cutoff = LocalDateTime.now().minusMinutes(5);
        userRepository.findAllByActiveFalseAndDeactivatedAtBefore(cutoff)
                .forEach(user -> {
                    userRepository.delete(user);
                    System.out.println("Deleted user: " + user.getEmail());
                });
    }
}
