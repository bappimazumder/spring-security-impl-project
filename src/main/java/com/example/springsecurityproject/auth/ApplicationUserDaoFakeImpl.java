package com.example.springsecurityproject.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.springsecurityproject.security.ApplicationUserRole.*;

@Repository("fakeRepository")
public class ApplicationUserDaoFakeImpl implements ApplicationUserDAO{

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationUserDaoFakeImpl(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String userName) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> applicationUser.getUsername().equals(userName))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        STUDENT.getGrantedAuthorities(),
                        "bappi",
                        passwordEncoder.encode("SecurityPassword"),
                        true,
                        true,
                        true,
                        true
                ),new ApplicationUser(
                ADMIN.getGrantedAuthorities(),
                "akash",
                 passwordEncoder.encode("SecurityPassword"),
                true,
                true,
                true,
                true
        ),new ApplicationUser(
                        ADMINTRANEE.getGrantedAuthorities(),
                        "adam",
                        passwordEncoder.encode("SecurityPassword"),
                        true,
                        true,
                        true,
                        true
                )
        );
        return applicationUsers;
    }
}
