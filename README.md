# ⚡ ESP32 Smart Electricity Billing System

A complete **Smart Electricity Billing System** built using ESP32 with a secure web interface, dynamic pricing, and demand-based billing.

---

## 🚀 Features

### 🔐 Security
- Strong password hashing (SHA-256 with 1000 iterations + salt)
- CSRF protection for all forms
- Session management with HttpOnly & SameSite cookies
- Rate limiting for login attempts

---

### 🌐 Web Interface
- Runs as a **Standalone WiFi Access Point**
- No internet required
- Admin and User dashboards

---

### 👤 User Roles

#### 👨‍💼 Admin
- Manage users
- Configure billing rates
- View demand analytics
- Export system data

#### 👤 User
- Add monthly electricity readings
- Preview bill before saving
- View billing history
- Edit/Delete records
- Export personal data

---

### ⚡ Smart Billing System
- Telescopic slab-based billing
- Categories:
  - Domestic
  - Commercial
  - Industrial

---

### 📊 Dynamic Pricing (Key Feature)
- Price adjusts based on total demand:
  - Low demand → price decreases
  - High demand → price increases
- Demand multiplier range: **0.8 to 1.5**

---

### 🧮 Bill Calculation Includes
- Energy Charges
- Fixed Charges
- Electricity Duty
- FAC (Fuel Adjustment Cost)
- Meter Rent

---

### 📈 Dashboard & Analytics
- Monthly demand visualization (Chart.js)
- Revenue tracking
- Consumption trends

---

### 💾 Persistent Storage
- Uses **LittleFS**
- Stores:
  - Users
  - Billing configuration
  - Consumption data

---

## 🛠️ Technologies Used

- ESP32 (Arduino Framework)
- C++
- LittleFS (File System)
- ArduinoJson
- WebServer Library
- mbedTLS (SHA-256)
- Chart.js (Frontend graphs)

---

## 📡 How It Works

1. ESP32 creates a WiFi Access Point  
2. User connects to the network  
3. Open browser → login page appears  
4. Admin/User performs operations  
5. System calculates bill using slabs + demand multiplier  
6. Data is saved permanently  

---

## 🔌 Setup Instructions

1. Install required libraries:
   - WiFi.h
   - WebServer.h
   - LittleFS.h
   - ArduinoJson
   - mbedTLS

2. Upload code to ESP32

3. After boot, connect to WiFi: 

SSID: SmartBilling Password: Haris@Secure123

4. Open browser and go to:http://192.168.4.1⁠

---

## 🔑 Default Login

Username: Haris 
Password: Asdfgh@123

---

## 📂 Project Structure

/users.json        → Stores user data /config.json       → Billing configuration /consumption.json  → User consumption records

---

## 🎯 Future Improvements

- Mobile app integration
- Real-time smart meter data
- Cloud synchronization
- Payment gateway integration

---

## 📌 Use Cases

- Smart grid systems
- Energy management systems
- IoT-based billing solutions
- Academic projects & research

---

## 👨‍💻 Author

**Haris Sheikh**

---

## ⭐ Note

This project demonstrates:
- Embedded systems + Web development
- Secure authentication system
- Real-world electricity billing logic
- Demand-based dynamic pricing

---

