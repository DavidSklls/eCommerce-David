package com.example.demo.controllers;

import com.example.demo.TestUtils;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.CreateUserRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static com.example.demo.TestUtils.createUser;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UserControllerTest {

    private final BCryptPasswordEncoder encoder = mock(BCryptPasswordEncoder.class);
    private final CartRepository cartRepository = mock(CartRepository.class);
    private UserController userController;
    private final UserRepository userRepository = mock(UserRepository.class);

    @Before
    public void init() {
        userController = new UserController();
        TestUtils.injectObjects(userController, "bCryptPasswordEncoder", encoder);
        TestUtils.injectObjects(userController, "cartRepository", cartRepository);
        TestUtils.injectObjects(userController, "userRepository", userRepository);
    }

    @Test
    public void createUserHappy() throws Exception {
        when(encoder.encode("Securepass")).thenReturn("Hash");
        CreateUserRequest userRequest = new CreateUserRequest();
        userRequest.setUsername("Name");
        userRequest.setPassword("Securepass");
        userRequest.setConfirmPassword("Securepass");

        ResponseEntity<User> response = userController.createUser(userRequest);

        Assert.assertNotNull(response);
        Assert.assertEquals(200, response.getStatusCodeValue());

        User u = response.getBody();
        Assert.assertNotNull(u);
        Assert.assertEquals(0, u.getId());
        Assert.assertEquals("Name", u.getUsername());
        Assert.assertEquals("Hash", u.getPassword());
    }

    @Test
    public void findByIdTest() {
        User user = createUser();
        when(userRepository.findById(4L)).thenReturn(Optional.of(user));
        ResponseEntity<User> response = userController.findById(4L);

        Assert.assertNotNull(response);
        Assert.assertEquals(user, response.getBody());
        Assert.assertEquals(200, response.getStatusCodeValue());
    }

    @Test
    public void notFoundByIdTest() {
        ResponseEntity<User> response = userController.findById(4L);
        Assert.assertNotNull(response);
        Assert.assertEquals(404, response.getStatusCodeValue());
    }

    @Test
    public void findByUsernameTest() {
        User user = createUser();
        when(userRepository.findByUsername("Name")).thenReturn(user);
        ResponseEntity<User> response = userController.findByUserName("Name");

        Assert.assertNotNull(response);
        Assert.assertEquals(200, response.getStatusCodeValue());
        Assert.assertEquals(user, response.getBody());
        Assert.assertEquals(4L, user.getId());
        Assert.assertEquals("Name", user.getUsername());
        Assert.assertEquals("Securepass", user.getPassword());
    }

    @Test
    public void notFoundByUsernameTest() {
        ResponseEntity<User> response = userController.findByUserName("Name");
        Assert.assertNotNull(response);
        Assert.assertEquals(404, response.getStatusCodeValue());
    }
}
