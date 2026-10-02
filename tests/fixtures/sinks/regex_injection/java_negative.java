package com.example.logs;

import java.util.List;
import java.util.regex.Pattern;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogSearchController {

    @GetMapping("/logs/search")
    public List<String> search(@RequestParam("q") String q) { // taint: route
        String expr = ".*" + Pattern.quote(q) + ".*";
        Pattern pattern = Pattern.compile(expr); // taint: sink
        return LogStore.lines().stream().filter(l -> pattern.matcher(l).matches()).toList();
    }
}
