package com.smartorders.userservice.user_service.exception;

public class InvalidUserDataException extends RuntimeException {

    public InvalidUserDataException(String message) {
        super(message);
    }
}
