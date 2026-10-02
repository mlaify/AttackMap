package com.example.config;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;

@RestController
public class ConfigController {

    @PostMapping("/config/preview")
    public Object preview(@RequestBody String body) { // taint: route
        Yaml yaml = new Yaml(); // taint: sink
        return yaml.load(body);
    }
}
