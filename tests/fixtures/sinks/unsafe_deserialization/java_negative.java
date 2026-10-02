package com.example.carts;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CartController {

    private final ObjectMapper mapper = new ObjectMapper();

    @PostMapping("/carts/restore")
    public int restore(HttpServletRequest request) throws IOException { // taint: route
        Cart cart = mapper.readValue(request.getInputStream(), Cart.class); // taint: sink
        return cart.size();
    }
}
