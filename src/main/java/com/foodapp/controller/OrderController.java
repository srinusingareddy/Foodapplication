package com.foodapp.controller;

import com.foodapp.model.*;
import com.foodapp.repository.*;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@CrossOrigin(origins = {
        "http://localhost:5173",
        "https://foodaplicationfrontend.onrender.com"
})
@RestController
@RequestMapping("/api/user/orders")
public class OrderController {
    @Autowired
    private CartRepository cartRepository;

    @Autowired
    private OrderRepository orderRepository;

    @Autowired
    private UserRepository userRepository;

    // 🟢 PLACE ORDER
    @PostMapping
    @Transactional
    public Order placeOrder(Authentication authentication) {

        String email = authentication.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<Cart> cartItems = cartRepository.findByUser(user);

        if (cartItems.isEmpty()) {
            throw new RuntimeException("Cart is empty");
        }

        Order order = new Order();
        order.setUser(user);
        order.setStatus("PLACED");
        order.setOrderTime(LocalDateTime.now());

        double total = 0;
        List<OrderItem> orderItems = new ArrayList<>();

        for (Cart cart : cartItems) {

            OrderItem item = new OrderItem();
            item.setOrder(order);
            item.setFoodItem(cart.getFoodItem());
            item.setQuantity(cart.getQuantity());
            item.setPrice(cart.getFoodItem().getPrice());

            total += cart.getQuantity() * cart.getFoodItem().getPrice();
            orderItems.add(item);
        }

        order.setTotalAmount(total);
        order.setOrderItems(orderItems);

        // ✅ ONLY SAVE ORDER (cascade saves items)
        Order savedOrder = orderRepository.save(order);

        // ✅ clear cart after successful order
        cartRepository.deleteAll(cartItems);

        return savedOrder;
    }

    // 🟢 VIEW USER ORDERS
    @GetMapping
    public List<Order> getMyOrders(Authentication authentication) {

        String email = authentication.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return orderRepository.findByUser(user);
    }
}
