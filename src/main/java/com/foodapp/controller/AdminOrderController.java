//package com.foodapp.controller;
//
//import com.foodapp.model.Order;
//import com.foodapp.model.OrderItem;
//import com.foodapp.repository.OrderRepository;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.web.bind.annotation.*;
//
//import java.time.LocalDateTime;
//import java.util.List;
//
//@CrossOrigin(origins = "http://localhost:5173")
//@RestController
//@RequestMapping("/api/admin/orders")
//public class AdminOrderController {
//
//    @Autowired
//    private OrderRepository orderRepository;
//
//    // ✅ simple request body for status update
//    public static class StatusRequest {
//        public String status;
//    }
//
//    // ✅ DTOs so admin can see user details + items safely
//    public record AdminOrderItemDTO(
//            Long id,
//            String foodName,
//            double price,
//            int quantity
//    ) {}
//
//    public record AdminOrderDTO(
//            Long id,
//            Long userId,
//            String userEmail,
//            String status,
//            double totalAmount,
//            LocalDateTime orderTime,
//            List<AdminOrderItemDTO> items
//    ) {}
//
//    // 🟢 VIEW ALL ORDERS (ADMIN) - return DTO
//    @GetMapping
//    public List<AdminOrderDTO> getAllOrders() {
//        return orderRepository.findAll().stream().map(o -> new AdminOrderDTO(
//                o.getId(),
//                o.getUser() != null ? o.getUser().getId() : null,
//                o.getUser() != null ? o.getUser().getEmail() : null,
//                o.getStatus(),
//                o.getTotalAmount(),
//                o.getOrderTime(),
//                o.getOrderItems() == null ? List.of() :
//                        o.getOrderItems().stream().map(this::toItemDTO).toList()
//        )).toList();
//    }
//
//    private AdminOrderItemDTO toItemDTO(OrderItem it) {
//        String foodName = (it.getFoodItem() != null) ? it.getFoodItem().getName() : "Item";
//        return new AdminOrderItemDTO(
//                it.getId(),
//                foodName,
//                it.getPrice(),
//                it.getQuantity()
//        );
//    }
//
//    // 🟡 UPDATE ORDER STATUS (JSON body)
//    @PutMapping("/{orderId}/status")
//    public Order updateOrderStatus(
//            @PathVariable Long orderId,
//            @RequestBody StatusRequest body
//    ) {
//        Order order = orderRepository.findById(orderId)
//                .orElseThrow(() -> new RuntimeException("Order not found"));
//
//        order.setStatus(body.status);
//        return orderRepository.save(order);
//    }
//}



package com.foodapp.controller;

import com.foodapp.model.Order;
import com.foodapp.model.OrderItem;
import com.foodapp.repository.OrderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@CrossOrigin(origins = {
        "http://localhost:5173",
        "https://foodaplicationfrontend.onrender.com"
})
@RestController
@RequestMapping("/api/admin/orders")
public class AdminOrderController {

    @Autowired
    private OrderRepository orderRepository;

    public static class StatusRequest {
        public String status;
    }

    public record AdminOrderItemDTO(
            Long id,
            String foodName,
            double price,
            int quantity
    ) {}

    public record AdminOrderDTO(
            Long id,
            Long userId,
            String userEmail,
            String status,
            double totalAmount,
            LocalDateTime orderTime,
            List<AdminOrderItemDTO> items
    ) {}

    @GetMapping
    public List<AdminOrderDTO> getAllOrders() {
        return orderRepository.findAll()
                .stream()
                .map(this::toOrderDTO)
                .toList();
    }

    @PutMapping("/{orderId}/status")
    public AdminOrderDTO updateOrderStatus(
            @PathVariable Long orderId,
            @RequestBody StatusRequest body
    ) {
        if (body == null || body.status == null || body.status.trim().isEmpty()) {
            throw new RuntimeException("Status is required");
        }

        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new RuntimeException("Order not found"));

        order.setStatus(body.status.trim());
        Order saved = orderRepository.save(order);

        return toOrderDTO(saved);
    }

    private AdminOrderDTO toOrderDTO(Order o) {
        return new AdminOrderDTO(
                o.getId(),
                o.getUser() != null ? o.getUser().getId() : null,
                o.getUser() != null ? o.getUser().getEmail() : null,
                o.getStatus(),
                o.getTotalAmount(),
                o.getOrderTime(),
                (o.getOrderItems() == null) ? List.of() :
                        o.getOrderItems().stream().map(this::toItemDTO).toList()
        );
    }

    private AdminOrderItemDTO toItemDTO(OrderItem it) {
        String foodName = (it.getFoodItem() != null && it.getFoodItem().getName() != null)
                ? it.getFoodItem().getName()
                : "Item";

        return new AdminOrderItemDTO(
                it.getId(),
                foodName,
                it.getPrice(),
                it.getQuantity()
        );
    }
}

