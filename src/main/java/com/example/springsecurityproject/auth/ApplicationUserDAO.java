package com.example.springsecurityproject.auth;


import java.util.Optional;

public interface ApplicationUserDAO {
    Optional<ApplicationUser> selectApplicationUserByUsername(String userName);
}
