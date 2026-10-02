package com.example.preview;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FetchController {

    @GetMapping("/fetch")
    public String fetch(HttpServletRequest request) throws IOException {
        String target = request.getParameter("url"); // taint: source
        URL url = new URL(target);
        try (InputStream in = url.openStream()) { // taint: sink
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
