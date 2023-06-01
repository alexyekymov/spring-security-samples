package dev.overlax.springsecuritysamples.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Developer {

    private Long id;
    private String firstName;
    private String last_name;
}
