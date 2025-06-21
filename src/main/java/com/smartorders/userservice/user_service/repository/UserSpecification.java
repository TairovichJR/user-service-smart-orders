package com.smartorders.userservice.user_service.repository;

import com.smartorders.userservice.user_service.dto.UserSearchRequest;
import com.smartorders.userservice.user_service.model.User;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

public class UserSpecification {

    public static Specification<User> build(UserSearchRequest request){
        return(root, query, cb) -> {
            Predicate predicate = cb.conjunction();

            if (request.getFirstName() != null && !request.getFirstName().isEmpty()) {
                predicate = cb.and(predicate, cb.like(cb.lower(root.get("firstName")), "%" + request.getFirstName().toLowerCase() + "%"));
            }
            if (request.getLastName() != null && !request.getLastName().isEmpty()) {
                predicate = cb.and(predicate, cb.like(cb.lower(root.get("lastName")), "%" + request.getLastName().toLowerCase() + "%"));
            }
            if (request.getEmail() != null && !request.getEmail().isEmpty()) {
                predicate = cb.and(predicate, cb.equal(cb.lower(root.get("email")), request.getEmail().toLowerCase()));
            }
            if (request.getRole() != null && !request.getRole().isEmpty()) {
                predicate = cb.and(predicate, cb.equal(root.get("role"), request.getRole()));
            }
            // Only filter by active if it is not null
            if (request.getIsActive() != null) {
                predicate = cb.and(predicate, cb.equal(root.get("active"), request.getIsActive()));
            }

            return predicate;
        };
    }
}