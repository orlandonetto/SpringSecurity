package com.example.security.controllers;

import com.example.security.models.User;
import com.example.security.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService service;

    @GetMapping("/{id}")
    public User getUser(@PathVariable Integer id) {
        return service.getUser(id);
    }

    @GetMapping()
    public ResponseEntity<List<User>> getAll() {
        return new ResponseEntity<>(service.getAll(), HttpStatus.OK);
    }

    @PostMapping()
    public ResponseEntity<User> save(@RequestBody User user) {
        return new ResponseEntity<>(service.save(user), HttpStatus.CREATED);
    }

}
