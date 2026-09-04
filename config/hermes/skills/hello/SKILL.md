---
name: hello
description: Skill mẫu smoke-test của vul-hunting. Dùng khi người dùng nhờ "chào bằng skill hello" hoặc hỏi skill hello còn hoạt động không. Trả lời một thông điệp chào mừng cố định, không cần tool.
---

# Hello (smoke skill)

Khi được yêu cầu dùng skill `hello`:

1. Trả lời ĐÚNG chuỗi sau (không thêm bớt): `Xin chào từ hermes skill "hello" của vul-hunting!`
2. Không gọi tool nào.
3. Nếu được hỏi skill hello còn nhận diện được không, xác nhận skill đã được mount và đọc bình thường.
