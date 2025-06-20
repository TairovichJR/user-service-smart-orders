package com.smartorders.userservice.user_service.repository;

import com.smartorders.userservice.user_service.dto.UserSearchRequest;
import com.smartorders.userservice.user_service.model.User;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

public class UserSpecification {

    public static Specification<User> build(UserSearchRequest request){
        return(root, query, cb) -> {
            Predicate predicate = cb.conjunction();

            if (request.getUserId() != null && request.getUserId() > 0) {
                predicate = cb.and(predicate, cb.equal(root.get("id"), request.getUserId()));
            }
            if (request.getName() != null && !request.getName().isEmpty()) {
                predicate = cb.and(predicate, cb.like(cb.lower(root.get("name")), "%" + request.getName().toLowerCase() + "%"));
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