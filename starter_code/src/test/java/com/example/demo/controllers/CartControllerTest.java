package com.example.demo.controllers;

import com.example.demo.TestUtils;
import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.ItemRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.ModifyCartRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Optional;

import static com.example.demo.TestUtils.*;
import static org.mockito.Mockito.*;

public class CartControllerTest {

    private CartController cartController;
    private final CartRepository cartRepository = mock(CartRepository.class);
    private final ItemRepository itemRepository = mock(ItemRepository.class);
    private final UserRepository userRepository = mock(UserRepository.class);

    @Before
    public void init() {
        cartController = new CartController();
        TestUtils.injectObjects(cartController, "cartRepository", cartRepository);
        TestUtils.injectObjects(cartController, "itemRepository", itemRepository);
        TestUtils.injectObjects(cartController, "userRepository", userRepository);
    }

    @Test
    public void addCartNoUser() {
        ModifyCartRequest modifyCartRequest = createModifyCartRequest("", 4, 4);
        ResponseEntity<Cart> responseEntity = cartController.addTocart(modifyCartRequest);

        Assert.assertNotNull(responseEntity);
        Assert.assertEquals(404, responseEntity.getStatusCodeValue());
    }

    @Test
    public void addCartNoItem() {
        when(itemRepository.findById(1L)).thenReturn(Optional.empty());
        when(userRepository.findByUsername("Name")).thenReturn(new User());

        ModifyCartRequest modifyCartRequest = createModifyCartRequest("Name", 4, 4);
        ResponseEntity<Cart> responseEntity = cartController.addTocart(modifyCartRequest);

        Assert.assertNotNull(responseEntity);
        verify(itemRepository, times(1)).findById(4L);
        Assert.assertEquals(404, responseEntity.getStatusCodeValue());
    }

    @Test
    public void addCartTest() {
        Item item = createItem();
        User user = createUser();
        Cart cart = user.getCart();
        cart.addItem(item);
        cart.setUser(user);
        user.setCart(cart);

        when(itemRepository.findById(4L)).thenReturn(Optional.of(item));
        when(userRepository.findByUsername("Name")).thenReturn(user);

        ModifyCartRequest modifyCartRequest = createModifyCartRequest("Name", 4, 4);
        ResponseEntity<Cart> responseEntity = cartController.addTocart(modifyCartRequest);

        Assert.assertNotNull(responseEntity);
        Assert.assertEquals(200, responseEntity.getStatusCodeValue());

        Cart responseCart = responseEntity.getBody();

        Assert.assertNotNull(responseCart);
        List<Item> items = responseCart.getItems();
        Assert.assertNotNull(items);
        Assert.assertEquals("Name", responseCart.getUser().getUsername());

        verify(cartRepository, times(1)).save(responseCart);
    }

    @Test
    public void removeCartNoUser() {
        ModifyCartRequest modifyCartRequest = createModifyCartRequest("", 4, 4);
        ResponseEntity<Cart> responseEntity = cartController.removeFromCart(modifyCartRequest);

        Assert.assertNotNull(responseEntity);
        Assert.assertEquals(404, responseEntity.getStatusCodeValue());
    }
        @Test
            public void removeCartNoItem() {
            when(itemRepository.findById(1L)).thenReturn(Optional.empty());
            when(userRepository.findByUsername("Name")).thenReturn(new User());

            ModifyCartRequest modifyCartRequest = createModifyCartRequest("Name", 4, 4);
            ResponseEntity<Cart> responseEntity = cartController.removeFromCart(modifyCartRequest);

            Assert.assertNotNull(responseEntity);
            verify(itemRepository, times(1)).findById(4L);
            Assert.assertEquals(404, responseEntity.getStatusCodeValue());
        }

        @Test
        public void removeCartTest() {
            Item item = createItem();
            User user = createUser();
            Cart cart = user.getCart();
            cart.addItem(item);
            cart.setUser(user);
            user.setCart(cart);

            when(itemRepository.findById(4L)).thenReturn(Optional.of(item));
            when(userRepository.findByUsername("Name")).thenReturn(user);

            ModifyCartRequest modifyCartRequest = createModifyCartRequest("Name", 4, 4);
            ResponseEntity<Cart> responseEntity = cartController.removeFromCart(modifyCartRequest);

            Assert.assertNotNull(responseEntity);
            Assert.assertEquals(200, responseEntity.getStatusCodeValue());

            Cart responseCart = responseEntity.getBody();

            Assert.assertNotNull(responseCart);
            List<Item> items = responseCart.getItems();
            Assert.assertNotNull(items);
            Assert.assertEquals(0, items.size());
            Assert.assertEquals("Name", responseCart.getUser().getUsername());

            verify(cartRepository, times(1)).save(responseCart);
        }
    }
