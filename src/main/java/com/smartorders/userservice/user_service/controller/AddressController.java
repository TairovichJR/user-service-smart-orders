package com.smartorders.userservice.user_service.controller;

import com.smartorders.userservice.user_service.dto.AddAddressRequest;
import com.smartorders.userservice.user_service.dto.AddressDto;
import com.smartorders.userservice.user_service.dto.UpdateAddressRequest;
import com.smartorders.userservice.user_service.service.AddressService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/v1/address")
@RequiredArgsConstructor
public class AddressController {

    private final AddressService addressService;

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @PostMapping("/add")
    public ResponseEntity<AddressDto> addAddressForUser(@RequestBody @Valid AddAddressRequest request) {
        AddressDto addressDto = addressService.addAddressForUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(addressDto);
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @PutMapping("/{addressId}/update")
    public ResponseEntity<AddressDto> updateAddressForUser(
            @PathVariable Long addressId,
            @RequestBody @Valid UpdateAddressRequest request) {
        AddressDto addressDto = addressService.updateAddressForUser(addressId, request);
        return ResponseEntity.ok(addressDto);
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @DeleteMapping("/{addressId}")
    public ResponseEntity<Void> deleteAddressForUser(
            @PathVariable Long addressId) {
        addressService.deleteAddressForUser(addressId);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @GetMapping("/{addressId}")
    public ResponseEntity<AddressDto> getAddressById(@PathVariable Long addressId) {
        AddressDto addressDto = addressService.getAddressById(addressId);
        return ResponseEntity.ok(addressDto);
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @GetMapping("/all")
    public ResponseEntity<List<AddressDto>> getAllAddressesForCurrentUser() {
        List<AddressDto> addresses = addressService.getAllAddressesForUser();
        return ResponseEntity.ok(addresses);
    }

    //Admin related endpoints
    @PreAuthorize("hasAnyRole('ADMIN')")
    @PostMapping("/{userId}/add")
    public ResponseEntity<AddressDto> addAddressForUserByAdmin(
            @PathVariable Long userId,
            @RequestBody @Valid AddAddressRequest request) {
        AddressDto addressDto = addressService.addAddressForUserByAdmin(userId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(addressDto);
    }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @PutMapping("/{userId}/{addressId}/update")
    public ResponseEntity<AddressDto> updateAddressForUserByAdmin(
            @PathVariable Long userId,
            @PathVariable Long addressId,
            @RequestBody @Valid UpdateAddressRequest request) {
        AddressDto addressDto = addressService.updateAddressForUserByAdmin(userId, addressId, request);
        return ResponseEntity.ok(addressDto);
    }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @DeleteMapping("/{userId}/{addressId}")
    public ResponseEntity<Void> deleteAddressForUserByAdmin(
            @PathVariable Long userId,
            @PathVariable Long addressId) {
        addressService.deleteAddressForUserByAdmin(userId, addressId);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @GetMapping("/{userId}/{addressId}")
    public ResponseEntity<AddressDto> getAddressByIdForUserByAdmin(
            @PathVariable Long userId,
            @PathVariable Long addressId) {
        AddressDto addressDto = addressService.getAddressByIdForUserByAdmin(userId, addressId);
        return ResponseEntity.ok(addressDto);
    }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @GetMapping("/{userId}/all")
    public ResponseEntity<List<AddressDto>> getAllAddressesForUserByAdmin(@PathVariable Long userId) {
        List<AddressDto> addresses = addressService.getAllAddressesForUserByAdmin(userId);
        return ResponseEntity.ok(addresses);
    }
}