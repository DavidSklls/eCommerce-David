package com.example.demo.controllers;

import com.example.demo.TestUtils;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.repositories.ItemRepository;
import org.assertj.core.api.Assertions;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static com.example.demo.TestUtils.createItem;
import static org.mockito.Mockito.*;

public class ItemControllerTest {

    private ItemController itemController;
    private final ItemRepository itemRepository = mock(ItemRepository.class);

    @Before
    public void init() {
        itemController = new ItemController();
        TestUtils.injectObjects(itemController, "itemRepository", itemRepository);
    }

    @Test
    public void getItemsTest() {
        ResponseEntity<List<Item>> response = itemController.getItems();
        List<Item> itemList = response.getBody();
        Assert.assertNotNull(response);
        Assert.assertEquals(200, response.getStatusCodeValue());
        Assert.assertNotNull(itemList);
    }

    @Test
    public void getItemByTest() {
        when(itemRepository.findById(4L)).thenReturn(Optional.of(createItem()));
        ResponseEntity<Item> response = itemController.getItemById(4L);

        Assert.assertNotNull(response);
        Assert.assertEquals(200, response.getStatusCodeValue());

        Item item = response.getBody();
        Assert.assertNotNull(item);
    }

    @Test
    public void getItemByName() {
        List<Item> items = new ArrayList<>();
        items.add(createItem());
        when(itemRepository.findByName("Item")).thenReturn(items);
        ResponseEntity<List<Item>> response = itemController.getItemsByName("Item");

        Assert.assertNotNull(response);
        Assert.assertEquals(200, response.getStatusCodeValue());
        Assert.assertEquals(items, response.getBody());
    }
}
