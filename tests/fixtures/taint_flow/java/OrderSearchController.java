package com.example.orders;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderSearchController {

    private final DataSource dataSource;

    public OrderSearchController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @GetMapping("/orders/search")
    public List<String> search(@RequestParam("q") String term) throws SQLException { // taint: source
        String sql = "SELECT sku FROM orders WHERE sku LIKE '%" + term + "%'";
        List<String> skus = new ArrayList<>();
        try (Statement stmt = dataSource.getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(sql)) { // taint: sink
            while (rs.next()) {
                skus.add(rs.getString("sku"));
            }
        }
        return skus;
    }
}
