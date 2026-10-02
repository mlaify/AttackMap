package com.example.admin;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @GetMapping("/admin/resource")
    public String describe(@RequestParam("name") String name) throws NamingException { // taint: route
        String jndiName = "java:comp/env/" + name;
        Object resource = new InitialContext().lookup(jndiName); // taint: sink
        return String.valueOf(resource);
    }
}
