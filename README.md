## 🟩 BACKEND README (Node.js + Express + MongoDB + Socket.io)

```md
# Chintu Chat – Backend

Node.js + Express + MongoDB backend for **Chintu Chat**, a realtime messaging application.

This service exposes a REST API for authentication & data management and a **Socket.io** server for realtime messaging.

---

## ✨ Features

- 🔐 JWT-based authentication (login / register / protected routes)
- 👤 User management (profiles, avatars, status)
- 💬 Realtime messaging using Socket.io
- 🧵 Conversation + message persistence in MongoDB
- 🟢 Online / offline user tracking
- 🛡 CORS, Helmet, and basic security best practices
- 📄 Centralized error handling & request logging

---

## 🛠 Tech Stack

- **Node.js** + **Express**
- **MongoDB** + **Mongoose**
- **Socket.io**
- **JSON Web Token (JWT)**
- **bcrypt** for password hashing
- **dotenv** for configuration
- Optional: **morgan** (logging), **helmet**, **cors**

