// Test fixture (#242): deliberately vulnerable.
package com.example;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity
public class User {
    @Id
    private Long id;
    private String name;
    private String role;
    private boolean isAdmin = false;
}
