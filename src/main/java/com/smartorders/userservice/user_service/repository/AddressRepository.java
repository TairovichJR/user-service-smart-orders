package com.smartorders.userservice.user_service.repository;

import com.smartorders.userservice.user_service.model.Address;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface AddressRepository extends JpaRepository<Address, Long> {
     List<Address> findByUserId(Long userId);
}