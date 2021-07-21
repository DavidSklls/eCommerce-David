package com.example.demo.controllers;

import com.example.demo.TestUtils;
import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.UserOrder;
import com.example.demo.model.persistence.repositories.OrderRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;

import java.util.ArrayList;
import java.util.List;

import static com.example.demo.TestUtils.createItem;
import static com.example.demo.TestUtils.createUser;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OrderControllerTest {

    private OrderController orderController;
    private final OrderRepository orderRepository = mock(OrderRepository.class);
    private final UserRepository userRepository = mock(UserRepository.class);

    @Before
    public void init() {
        orderController = new OrderController();
        TestUtils.injectObjects(orderController, "orderRepository", orderRepository);
        TestUtils.injectObjects(orderController, "userRepository", userRepository);
    }

    @Test
    public void submitTest() {
        Item item = createItem();
        User user = createUser();
        Cart cart = user.getCart();

        List<Item> itemList = new ArrayList<>();
        itemList.add(item);
        cart.setItems(itemList);

        user.setCart(cart);
        cart.setUser(user);

        when(userRepository.findByUsername("Name")).thenReturn(user);
        ResponseEntity<UserOrder> response = orderController.submit("Name");

        Assert.assertNotNull(response);
        Assert.assertEquals(200, response.getStatusCodeValue());

        UserOrder retrievedUserOrder = response.getBody();
        Assert.assertNotNull(retrievedUserOrder.getTotal());
        Assert.assertNotNull(retrievedUserOrder.getUser());
        Assert.assertNotNull(retrievedUserOrder);
        Assert.assertNotNull(retrievedUserOrder.getItems());
    }

    @Test
    public void testSubmitNullUser(){
        Item item = createItem();
        User user = createUser();
        Cart cart = user.getCart();

        user.setCart(cart);
        cart.setUser(user);

        List<Item> itemList = new ArrayList<>();
        itemList.add(item);
        cart.setItems(itemList);

        when(userRepository.findByUsername("Name")).thenReturn(null);

        ResponseEntity<UserOrder> response = orderController.submit("Name");

        Assert.assertNotNull(response);
        Assert.assertEquals(404, response.getStatusCodeValue());
    }

    @Test
    public void ordersByUserTest() {
        Item item = createItem();
        User user = createUser();
        Cart cart = user.getCart();

        List<Item> itemList = new ArrayList<>();
        itemList.add(item);
        cart.setItems(itemList);

        user.setCart(cart);
        cart.setUser(user);

        when(userRepository.findByUsername("Name")).thenReturn(user);
        orderController.submit("Name");
        ResponseEntity<List<UserOrder>> responseEntity = orderController.getOrdersForUser("Name");

        List<UserOrder> userOrders = responseEntity.getBody();
        Assert.assertNotNull(responseEntity);
        Assert.assertNotNull(userOrders);
        Assert.assertEquals(0, userOrders.size());
        Assert.assertEquals(200, responseEntity.getStatusCodeValue());
    }

    @Test
    public void ordersByUserNullUser() {
        Item item = createItem();
        User user = createUser();
        Cart cart = user.getCart();

        user.setCart(cart);
        cart.setUser(user);

        List<Item> itemList = new ArrayList<>();
        itemList.add(item);
        cart.setItems(itemList);

        when(userRepository.findByUsername("Name")).thenReturn(null);
        orderController.submit("Name");
        ResponseEntity<List<UserOrder>> responseEntity = orderController.getOrdersForUser("Name");

        Assert.assertNotNull(responseEntity);
        Assert.assertEquals(404, responseEntity.getStatusCodeValue());
    }
}
