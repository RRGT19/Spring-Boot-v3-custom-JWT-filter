package com.example.repository;

import com.example.payload.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class UserRepository {

    public User findByUsername(String username) {
        User user = new User();
        user.setId("1");
        user.setUsername(username);
        user.setPassword("123");
        return user;
    }

}
