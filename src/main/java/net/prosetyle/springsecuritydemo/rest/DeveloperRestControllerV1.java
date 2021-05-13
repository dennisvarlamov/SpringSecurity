package net.prosetyle.springsecuritydemo.rest;

import net.prosetyle.springsecuritydemo.model.Developer;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/api/v1/developers")
public class DeveloperRestControllerV1 {

    private List<Developer> DEVELOPERS = Stream.of(
            new Developer(1L, "Dennis", "Varlamov"),
            new Developer(2L, "Sergey", "Sergeev"),
            new Developer(3L, "Alex", "Potashev")
    ).collect(Collectors.toList());

    @GetMapping
    public List<Developer> getAll() {
        return DEVELOPERS;
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority(('developers:read'))")
    public Developer getById(@PathVariable("id") Long id) {
        return DEVELOPERS.stream()
                .filter(d -> d.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority(('developers:write'))")
    public Developer create(@RequestBody Developer developer) {
        this.DEVELOPERS.add(developer);
        return developer;
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority(('developers:write'))")
    public void delete(@PathVariable("id") Long id) {
        this.DEVELOPERS.removeIf(developer -> developer.getId().equals(id));
    }

}
