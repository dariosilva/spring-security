package guru.sfg.brewery.bootstrap;

import guru.sfg.brewery.domain.security.Authority;
import guru.sfg.brewery.domain.security.Role;
import guru.sfg.brewery.domain.security.User;
import guru.sfg.brewery.repositories.security.AuthorityRepository;
import guru.sfg.brewery.repositories.security.RoleRepository;
import guru.sfg.brewery.repositories.security.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by jt on 6/21/20.
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class UserDataLoader implements CommandLineRunner {

    private final AuthorityRepository authorityRepository;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private void loadSecurityData() {
        //beer auths
        var createBeer = authorityRepository.save(Authority.builder().permission("beer.create").build());
        var readBeer = authorityRepository.save(Authority.builder().permission("beer.read").build());
        var updateBeer = authorityRepository.save(Authority.builder().permission("beer.update").build());
        var deleteBeer = authorityRepository.save(Authority.builder().permission("beer.delete").build());

        //customer auths
        var createCustomer = authorityRepository.save(Authority.builder().permission("customer.create").build());
        var readCustomer = authorityRepository.save(Authority.builder().permission("customer.read").build());
        var updateCustomer = authorityRepository.save(Authority.builder().permission("customer.update").build());
        var deleteCustomer = authorityRepository.save(Authority.builder().permission("customer.delete").build());

        //customer brewery
        var createBrewery = authorityRepository.save(Authority.builder().permission("brewery.create").build());
        var readBrewery = authorityRepository.save(Authority.builder().permission("brewery.read").build());
        var updateBrewery = authorityRepository.save(Authority.builder().permission("brewery.update").build());
        var deleteBrewery = authorityRepository.save(Authority.builder().permission("brewery.delete").build());

        var adminRole = roleRepository.save(Role.builder().name("ADMIN").build());
        var customerRole = roleRepository.save(Role.builder().name("CUSTOMER").build());
        var userRole = roleRepository.save(Role.builder().name("USER").build());

        adminRole.setAuthorities(new HashSet<>(Set.of(createBeer, updateBeer, readBeer, deleteBeer, createCustomer, readCustomer,
                updateCustomer, deleteCustomer, createBrewery, readBrewery, updateBrewery, deleteBrewery)));

        customerRole.setAuthorities(new HashSet<>(Set.of(readBeer, readCustomer, readBrewery)));

        userRole.setAuthorities(new HashSet<>(Set.of(readBeer)));

        roleRepository.saveAll(Arrays.asList(adminRole, customerRole, userRole));

        userRepository.save(User.builder()
                .username("spring")
                .password(passwordEncoder.encode("guru"))
                .role(adminRole)
                .build());

        userRepository.save(User.builder()
                .username("user")
                .password(passwordEncoder.encode("password"))
                .role(userRole)
                .build());

        userRepository.save(User.builder()
                .username("scott")
                .password(passwordEncoder.encode("tiger"))
                .role(customerRole)
                .build());

        log.debug("Users Loaded: " + userRepository.count());
    }

    @Transactional
    @Override
    public void run(String... args) {
        if (authorityRepository.count() == 0) {
            loadSecurityData();
        }
    }
}
