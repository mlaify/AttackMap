package com.example.orders;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// #242: object-level authorization in a method-security expression that
// checks the requested id against the authenticated principal.
@RestController
@RequestMapping("/api/orders")
public class OrderController {
    private final OrderRepository orders;

    public OrderController(OrderRepository orders) {
        this.orders = orders;
    }

    @GetMapping("/{id}")
    @PreAuthorize("@orderSecurity.isOwner(#id, authentication)")
    public Order get(@PathVariable Long id) {
        return orders.findById(id).orElseThrow();
    }
}
