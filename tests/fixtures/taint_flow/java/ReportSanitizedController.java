package com.example.reports;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReportSanitizedController {

    private static final String REPORT_DIR = "/srv/reports";

    @GetMapping("/reports/download")
    public byte[] download(@RequestParam("name") String name) throws IOException { // taint: source
        String safe = FilenameUtils.getName(name);
        Path report = Paths.get(REPORT_DIR, safe);
        return Files.readAllBytes(report); // taint: sink
    }
}
