package com.example.preview;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class FetchSanitizedController {

    private static final Set<String> ALLOWED_HOSTS = Set.of("api.partner.example");

    @GetMapping("/fetch")
    public String fetch(HttpServletRequest request) throws IOException {
        String target = request.getParameter("url"); // taint: source
        URL url = new URL(target);
        if (!ALLOWED_HOSTS.contains(url.getHost())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "host not allowed");
        }
        try (InputStream in = url.openStream()) { // taint: sink
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
