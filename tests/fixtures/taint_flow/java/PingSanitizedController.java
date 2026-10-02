package com.example.diag;

import java.io.IOException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PingSanitizedController {

    @PostMapping("/diag/ping")
    public String ping(@RequestParam String host) throws IOException { // taint: source
        if (!host.matches("^[a-z0-9.-]+$")) {
            throw new IllegalArgumentException("invalid host");
        }
        String command = "ping -c 1 " + host;
        Process proc = Runtime.getRuntime().exec(new String[] {"sh", "-c", command}); // taint: sink
        return new String(proc.getInputStream().readAllBytes());
    }
}
