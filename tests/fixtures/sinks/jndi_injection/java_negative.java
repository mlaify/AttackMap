package com.example.admin;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @GetMapping("/admin/resource")
    public String describe() throws NamingException { // taint: route
        Object resource = new InitialContext().lookup("java:comp/env/jdbc/orders"); // taint: sink
        return String.valueOf(resource);
    }
}
