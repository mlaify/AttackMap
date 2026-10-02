package com.example.exports;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExportController {

    @GetMapping("/exports/csv")
    public String export(@RequestParam("name") String name, HttpServletResponse response) { // taint: route
        String disposition = "attachment; filename=" + URLEncoder.encode(name, StandardCharsets.UTF_8) + ".csv";
        response.setHeader("Content-Disposition", disposition); // taint: sink
        return "id,total\n";
    }
}
