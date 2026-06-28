# 🛡️ Secrust

**Secrust** is a lightweight web security monitoring and log analysis platform built with **Go (Gin Framework)** and **SQLite**. It enables developers and security professionals to monitor websites, collect logs, detect suspicious activities, and manage multiple websites from a centralized dashboard.

---

## ✨ Features

* 🔐 User Authentication
* 🌐 Website Management
* 📊 Security Dashboard
* 📜 Log Collection API
* 🔍 Log Search
* 🚨 Alert Management
* ⚡ Lightweight SQLite Database
* 🐳 Docker Support
* 🎨 Responsive Web Interface

---

## 🛠️ Tech Stack

### Backend

* Go 1.25
* Gin Framework
* SQLite (modernc.org/sqlite)

### Frontend

* HTML
* CSS
* JavaScript

### Deployment

* Docker
* GitHub

---

## 📂 Project Structure

```
secrust/
│
├── internal/
│   ├── alerts/
│   ├── auth/
│   ├── dashboard/
│   ├── database/
│   ├── logs/
│   ├── middleware/
│   ├── realtime/
│   └── website/
│
├── static/
│
├── templates/
│
├── main.go
├── Dockerfile
├── go.mod
└── README.md
```

---

## 🚀 Getting Started

### Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/secrust.git
cd secrust
```

---

### Install Dependencies

```bash
go mod tidy
```

---

### Run Locally

```bash
go run main.go
```

Open:

```
http://localhost:8080
```

---

## 🐳 Run with Docker

### Build Image

```bash
docker build -t secrust .
```

### Run Container

```bash
docker run -d -p 8080:8080 --name secrust secrust
```

---

## 📡 Log Ingestion API

Example request:

```http
POST /api/logs
Content-Type: application/json
```

Example JSON:

```json
{
  "api_key": "YOUR_API_KEY",
  "ip": "192.168.1.100",
  "method": "GET",
  "path": "/login",
  "status": 200,
  "user_agent": "Mozilla/5.0"
}
```

---

## 📸 Screenshots

Add screenshots of:

* Login Page
* Dashboard
* Website Management
* Logs
* Alerts

---

## 🔮 Roadmap

* Real-time monitoring
* Email notifications
* WebSocket live logs
* Threat intelligence integration
* Geo-IP lookup
* Attack detection
* Rate limiting analytics
* REST API improvements
* JWT authentication
* Multi-user support

---

## 🤝 Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push your branch
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

**Parag Malvi**

* GitHub: https://github.com/YOUR_USERNAME
* LinkedIn: https://linkedin.com/in/YOUR_PROFILE

---

⭐ If you find this project useful, consider giving it a **Star** on GitHub!
