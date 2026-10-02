package com.example.orders;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import javax.sql.DataSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderLookupController {

    private final DataSource dataSource;

    public OrderLookupController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @GetMapping("/orders/lookup")
    public String lookup(HttpServletRequest request) throws SQLException {
        int id = Integer.parseInt(request.getParameter("id")); // taint: source
        String sql = "SELECT sku FROM orders WHERE id = " + id;
        try (Statement stmt = dataSource.getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(sql)) { // taint: sink
            return rs.next() ? rs.getString("sku") : null;
        }
    }
}
