package com.smartorders.userservice.user_service.exception;

public class UserNotActiveException extends RuntimeException {

    public UserNotActiveException(String message) {
        super(message);
    }
}
