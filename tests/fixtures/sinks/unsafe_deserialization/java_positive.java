package com.example.carts;

import java.io.IOException;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CartController {

    @PostMapping("/carts/restore")
    public int restore(HttpServletRequest request) throws IOException, ClassNotFoundException { // taint: route
        try (ObjectInputStream in = new ObjectInputStream(request.getInputStream())) { // taint: sink
            Cart cart = (Cart) in.readObject();
            return cart.size();
        }
    }
}
