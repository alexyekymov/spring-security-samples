package dev.overlax.springsecuritydemo.rest;

import dev.overlax.springsecuritydemo.model.Developer;
import dev.overlax.springsecuritydemo.model.Permission;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/api/v1/developers")
public class DeveloperRestControllerV1 {

    private List<Developer> DEVELOPERS = Stream.of(
            new Developer(1L, "Ivan", "Ivanov"),
            new Developer(2L, "Sergey", "Sergeev"),
            new Developer(3L, "Petr", "Petrov"),
            new Developer(4L, "Alex", "Alexeev")
    ).collect(Collectors.toList());

    @GetMapping
    public List<Developer> getAll() {
        return DEVELOPERS;
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('developer:read')")
    public Developer getById(@PathVariable Long id) {
        return DEVELOPERS.stream().filter(d -> d.getId().equals(id))
                .findFirst().orElse(null);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('developer:write')")
    public Developer create(@RequestBody Developer developer) {
        this.DEVELOPERS.add(developer);
        return developer;
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('developer:write')")
    public void delete(@PathVariable Long id) {
        this.DEVELOPERS.removeIf(d -> d.getId().equals(id));
    }
}
