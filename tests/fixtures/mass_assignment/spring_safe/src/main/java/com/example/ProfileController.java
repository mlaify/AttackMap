// Test fixture (#242): safe binders.
package com.example;

import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

@Controller
public class ProfileController {
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        binder.setAllowedFields("name");
    }

    @PostMapping("/profile")
    public String save(@ModelAttribute Account account) {
        return "ok";
    }
}
