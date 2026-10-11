// Test fixture (#242): deliberately vulnerable.
package com.example;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class UserController {
    @PostMapping("/users")
    public String create(@ModelAttribute User user) {
        return "ok";
    }

    @PutMapping("/api/users/{id}")
    public User update(@PathVariable Long id, @Valid @RequestBody User user) {
        return user;
    }

    @GetMapping("/users/search")
    public String search(@ModelAttribute User probe) {
        return "ok";
    }
}
