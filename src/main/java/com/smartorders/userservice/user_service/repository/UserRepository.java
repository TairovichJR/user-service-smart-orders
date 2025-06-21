package com.smartorders.userservice.user_service.repository;

import com.smartorders.userservice.user_service.model.Role;
import com.smartorders.userservice.user_service.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {

    Optional<User> findByEmail(String email);
    List<User> findByRole(Role role);
    Optional<User> findByEmailAndActiveTrue(String email);
    List<User> findAllByActiveFalseAndDeactivatedAtBefore(LocalDateTime cutoff);
    Optional<User> findByResetToken(String resetToken);

}