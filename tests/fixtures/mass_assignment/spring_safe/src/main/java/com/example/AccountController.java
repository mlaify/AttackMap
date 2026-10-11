// Test fixture (#242): safe binders.
package com.example;

import org.springframework.web.bind.annotation.*;

@RestController
public class AccountController {
    @PostMapping("/accounts")
    public Account create(@RequestBody Account account) {
        return account;
    }

    @PostMapping("/accounts/form")
    public Account form(@RequestBody AccountForm form) {
        return null;
    }
}
