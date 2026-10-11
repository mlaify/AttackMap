// Test fixture (#242): safe binders.
package com.example;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Entity;

@Entity
public class Account {
    private Long id;
    private String name;
    @JsonIgnore
    private String role;
}
