

#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <map>
#include <vector>
#include <algorithm>
#include <cmath>
#include "mbedtls/sha256.h"

// ========== Configuration ==========
const char* AP_SSID = "SmartBilling";
const char* AP_PASS = "Haris@Secure123";
IPAddress apIP(192, 168, 4, 1);
IPAddress netMsk(255, 255, 255, 0);

const unsigned long SESSION_TIMEOUT = 30 * 60 * 1000;  // 30 minutes
const int MAX_LOGIN_ATTEMPTS = 5;
const unsigned long RATE_LIMIT_BLOCK_MS = 5 * 60 * 1000;

// File paths
const char* USERS_FILE = "/users.json";
const char* CONFIG_FILE = "/config.json";
const char* CONSUMPTION_FILE = "/consumption.json";

// Default billing configuration (base slab rates)
const int SLAB_LIMITS[] = {100, 200, 500};
const float DOMESTIC_BASE_RATES[] = {4.0, 6.0, 7.5, 9.0};
const float COMMERCIAL_BASE_RATES[] = {6.0, 8.0, 10.0, 12.0};
const float INDUSTRIAL_BASE_RATES[] = {7.0, 9.0, 11.0, 13.0};
const float DEFAULT_FIXED_CHARGE = 50.0;
const float DEFAULT_DUTY_PERCENT = 5.0;
const float DEFAULT_FAC_RATE = 0.0;
const float DEFAULT_METER_RENT = 0.0;

// Demand simulation parameters
const float DEMAND_THRESHOLD_LOW = 5000.0;    // units per month – below → decrease price
const float DEMAND_THRESHOLD_HIGH = 10000.0;  // above → increase price
const float PRICE_MULTIPLIER_MIN = 0.8;
const float PRICE_MULTIPLIER_MAX = 1.5;
const float PRICE_ADJUSTMENT_STEP = 0.05;

// ========== Data Structures ==========
struct User {
  String id;
  String username;
  String passwordHash;
  String role;          // "admin" or "user"
  String category;      // "domestic", "commercial", "industrial"
  unsigned long createdAt;
};

struct BillingConfig {
  float fixedCharge;
  float dutyPercent;
  float facRate;
  float meterRent;
  float slabLimits[4];
  float domesticRates[4];
  float commercialRates[4];
  float industrialRates[4];
  int slabCount;
  float demandMultiplier;   // current price multiplier (0.8 .. 1.5)
};

struct ConsumptionRecord {
  String userId;
  String month;         // format "YYYY-MM"
  float units;
  float billAmount;
  float energyCharges;
  float fixedCharge;
  float dutyAmount;
  float facAmount;
  float meterRent;
  float appliedMultiplier;
  unsigned long timestamp;
};

// Global storage
std::map<String, User> users;
std::vector<ConsumptionRecord> consumptions;
BillingConfig config;

// Session management
struct Session {
  String username;
  String role;
  unsigned long lastUsed;
  String csrfToken;
};
std::map<String, Session> sessions;

// Rate limiting
struct Attempt {
  int count;
  unsigned long firstAttempt;
};
std::map<String, Attempt> loginAttempts;

// Web server
WebServer server(80);

// Forward declarations
int countAdmins();
float getBaseRate(const String& category, int slabIndex);
void updateDemandMultiplier();

// ========== Helper Functions ==========
String sha256(const String& input) {
  unsigned char shaResult[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0);
  mbedtls_sha256_update_ret(&ctx, (const unsigned char*)input.c_str(), input.length());
  mbedtls_sha256_finish_ret(&ctx, shaResult);
  mbedtls_sha256_free(&ctx);

  char hex[65];
  for (int i = 0; i < 32; i++) {
    sprintf(hex + (i * 2), "%02x", shaResult[i]);
  }
  hex[64] = '\0';
  return String(hex);
}

String strongHash(const String& password, const String& salt) {
  String hash = password + salt;
  for (int i = 0; i < 1000; i++) {
    hash = sha256(hash);
  }
  return hash;
}

bool constantTimeEqual(const String& a, const String& b) {
  if (a.length() != b.length()) return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < a.length(); i++) {
    diff |= (uint8_t)(a[i] ^ b[i]);
  }
  return diff == 0;
}

String generateToken() {
  uint8_t randomBytes[16];
  esp_fill_random(randomBytes, 16);
  char hex[33];
  for (int i = 0; i < 16; i++) {
    sprintf(hex + (i * 2), "%02x", randomBytes[i]);
  }
  return String(hex);
}

String generateId() {
  uint32_t r = esp_random();
  return String(millis(), HEX) + String(r, HEX);
}

float getBaseRate(const String& category, int slabIndex) {
  if (category == "commercial") {
    return config.commercialRates[slabIndex];
  } else if (category == "industrial") {
    return config.industrialRates[slabIndex];
  } else {
    return config.domesticRates[slabIndex];
  }
}

void updateDemandMultiplier() {
  // Calculate total units consumed in the last 30 days (approx)
  unsigned long now = millis();
  unsigned long oneMonthAgo = now - 30UL * 24 * 60 * 60 * 1000;
  float totalUnits = 0;
  for (auto& r : consumptions) {
    if (r.timestamp >= oneMonthAgo) {
      totalUnits += r.units;
    }
  }
  // If no consumption in last month, use overall average to avoid division by zero
  if (totalUnits == 0) {
    for (auto& r : consumptions) {
      totalUnits += r.units;
    }
    if (totalUnits == 0) totalUnits = 1; // fallback
  }

  float newMultiplier = config.demandMultiplier;
  if (totalUnits > DEMAND_THRESHOLD_HIGH) {
    newMultiplier += PRICE_ADJUSTMENT_STEP;
  } else if (totalUnits < DEMAND_THRESHOLD_LOW) {
    newMultiplier -= PRICE_ADJUSTMENT_STEP;
  }
  // Clamp
  if (newMultiplier < PRICE_MULTIPLIER_MIN) newMultiplier = PRICE_MULTIPLIER_MIN;
  if (newMultiplier > PRICE_MULTIPLIER_MAX) newMultiplier = PRICE_MULTIPLIER_MAX;
  config.demandMultiplier = newMultiplier;
  saveConfig();
}

// ========== Billing Calculation with Dynamic Pricing ==========
float calculateBill(float units, const BillingConfig& cfg, const String& category,
                    float& energyCharges, float& fixedCharge,
                    float& dutyAmount, float& facAmount, float& meterRent, float& multiplier) {
  multiplier = cfg.demandMultiplier;
  energyCharges = 0;
  float remaining = units;
  float prevLimit = 0;

  for (int i = 0; i < cfg.slabCount; i++) {
    float limit = cfg.slabLimits[i];
    float baseRate = getBaseRate(category, i);
    float rate = baseRate * multiplier;
    float slabUnits = 0;
    if (remaining > (limit - prevLimit)) {
      slabUnits = limit - prevLimit;
    } else {
      slabUnits = remaining;
    }
    if (slabUnits > 0) {
      energyCharges += slabUnits * rate;
      remaining -= slabUnits;
    }
    prevLimit = limit;
    if (remaining <= 0) break;
  }
  if (remaining > 0 && cfg.slabCount > 0) {
    float lastBaseRate = getBaseRate(category, cfg.slabCount - 1);
    float lastRate = lastBaseRate * multiplier;
    energyCharges += remaining * lastRate;
  }

  fixedCharge = cfg.fixedCharge;
  facAmount = units * cfg.facRate;
  dutyAmount = energyCharges * (cfg.dutyPercent / 100.0);
  meterRent = cfg.meterRent;
  float total = energyCharges + fixedCharge + facAmount + dutyAmount + meterRent;
  return total;
}

// ========== Persistent Storage ==========
bool loadUsers() {
  if (!LittleFS.exists(USERS_FILE)) return false;
  File file = LittleFS.open(USERS_FILE, "r");
  if (!file) return false;

  DynamicJsonDocument doc(8192);
  DeserializationError error = deserializeJson(doc, file);
  file.close();
  if (error) return false;

  users.clear();
  JsonArray arr = doc.as<JsonArray>();
  for (JsonObject obj : arr) {
    User u;
    u.id = obj["id"].as<String>();
    u.username = obj["username"].as<String>();
    u.passwordHash = obj["passwordHash"].as<String>();
    u.role = obj["role"].as<String>();
    u.category = obj["category"] | "domestic";
    u.createdAt = obj["createdAt"].as<unsigned long>();
    users[u.username] = u;
  }
  return true;
}

bool saveUsers() {
  DynamicJsonDocument doc(8192);
  JsonArray arr = doc.to<JsonArray>();
  for (auto& p : users) {
    User& u = p.second;
    JsonObject obj = arr.createNestedObject();
    obj["id"] = u.id;
    obj["username"] = u.username;
    obj["passwordHash"] = u.passwordHash;
    obj["role"] = u.role;
    obj["category"] = u.category;
    obj["createdAt"] = u.createdAt;
  }

  File file = LittleFS.open(USERS_FILE, "w");
  if (!file) return false;
  serializeJson(doc, file);
  file.close();
  return true;
}

bool loadConfig() {
  if (!LittleFS.exists(CONFIG_FILE)) {
    config.fixedCharge = DEFAULT_FIXED_CHARGE;
    config.dutyPercent = DEFAULT_DUTY_PERCENT;
    config.facRate = DEFAULT_FAC_RATE;
    config.meterRent = DEFAULT_METER_RENT;
    config.slabCount = 4;
    for (int i = 0; i < 3; i++) config.slabLimits[i] = SLAB_LIMITS[i];
    for (int i = 0; i < 4; i++) {
      config.domesticRates[i] = DOMESTIC_BASE_RATES[i];
      config.commercialRates[i] = COMMERCIAL_BASE_RATES[i];
      config.industrialRates[i] = INDUSTRIAL_BASE_RATES[i];
    }
    config.demandMultiplier = 1.0;
    return true;
  }

  File file = LittleFS.open(CONFIG_FILE, "r");
  if (!file) return false;

  DynamicJsonDocument doc(2048);
  DeserializationError error = deserializeJson(doc, file);
  file.close();
  if (error) return false;

  config.fixedCharge = doc["fixedCharge"] | DEFAULT_FIXED_CHARGE;
  config.dutyPercent = doc["dutyPercent"] | DEFAULT_DUTY_PERCENT;
  config.facRate = doc["facRate"] | DEFAULT_FAC_RATE;
  config.meterRent = doc["meterRent"] | DEFAULT_METER_RENT;
  config.slabCount = min((int)(doc["slabCount"] | 4), 4);
  config.demandMultiplier = doc["demandMultiplier"] | 1.0;

  JsonArray limits = doc["slabLimits"];
  JsonArray domestic = doc["domesticRates"];
  JsonArray commercial = doc["commercialRates"];
  JsonArray industrial = doc["industrialRates"];
  for (int i = 0; i < min(config.slabCount, 4); i++) {
    config.slabLimits[i] = limits[i] | SLAB_LIMITS[i];
    config.domesticRates[i] = domestic[i] | DOMESTIC_BASE_RATES[i];
    config.commercialRates[i] = commercial[i] | COMMERCIAL_BASE_RATES[i];
    config.industrialRates[i] = industrial[i] | INDUSTRIAL_BASE_RATES[i];
  }
  return true;
}

bool saveConfig() {
  DynamicJsonDocument doc(2048);
  doc["fixedCharge"] = config.fixedCharge;
  doc["dutyPercent"] = config.dutyPercent;
  doc["facRate"] = config.facRate;
  doc["meterRent"] = config.meterRent;
  doc["slabCount"] = config.slabCount;
  doc["demandMultiplier"] = config.demandMultiplier;

  JsonArray limits = doc.createNestedArray("slabLimits");
  JsonArray domestic = doc.createNestedArray("domesticRates");
  JsonArray commercial = doc.createNestedArray("commercialRates");
  JsonArray industrial = doc.createNestedArray("industrialRates");
  for (int i = 0; i < config.slabCount; i++) {
    limits.add(config.slabLimits[i]);
    domestic.add(config.domesticRates[i]);
    commercial.add(config.commercialRates[i]);
    industrial.add(config.industrialRates[i]);
  }

  File file = LittleFS.open(CONFIG_FILE, "w");
  if (!file) return false;
  serializeJson(doc, file);
  file.close();
  return true;
}

bool loadConsumptions() {
  if (!LittleFS.exists(CONSUMPTION_FILE)) return false;
  File file = LittleFS.open(CONSUMPTION_FILE, "r");
  if (!file) return false;

  DynamicJsonDocument doc(8192);
  DeserializationError error = deserializeJson(doc, file);
  file.close();
  if (error) return false;

  consumptions.clear();
  JsonArray arr = doc.as<JsonArray>();
  for (JsonObject obj : arr) {
    ConsumptionRecord r;
    r.userId = obj["userId"].as<String>();
    r.month = obj["month"].as<String>();
    r.units = obj["units"].as<float>();
    r.billAmount = obj["billAmount"].as<float>();
    r.energyCharges = obj["energyCharges"].as<float>();
    r.fixedCharge = obj["fixedCharge"].as<float>();
    r.dutyAmount = obj["dutyAmount"].as<float>();
    r.facAmount = obj["facAmount"].as<float>();
    r.meterRent = obj["meterRent"] | 0.0f;
    r.appliedMultiplier = obj["appliedMultiplier"] | 1.0f;
    r.timestamp = obj["timestamp"].as<unsigned long>();
    consumptions.push_back(r);
  }
  return true;
}

bool saveConsumptions() {
  DynamicJsonDocument doc(8192);
  JsonArray arr = doc.to<JsonArray>();
  for (auto& r : consumptions) {
    JsonObject obj = arr.createNestedObject();
    obj["userId"] = r.userId;
    obj["month"] = r.month;
    obj["units"] = r.units;
    obj["billAmount"] = r.billAmount;
    obj["energyCharges"] = r.energyCharges;
    obj["fixedCharge"] = r.fixedCharge;
    obj["dutyAmount"] = r.dutyAmount;
    obj["facAmount"] = r.facAmount;
    obj["meterRent"] = r.meterRent;
    obj["appliedMultiplier"] = r.appliedMultiplier;
    obj["timestamp"] = r.timestamp;
  }

  File file = LittleFS.open(CONSUMPTION_FILE, "w");
  if (!file) return false;
  serializeJson(doc, file);
  file.close();
  return true;
}

// ========== Session & Rate Limiting ==========
String getSessionToken() {
  if (server.hasHeader("Cookie")) {
    String cookie = server.header("Cookie");
    int idx = cookie.indexOf("session_token=");
    if (idx != -1) {
      int start = idx + 14;
      int end = cookie.indexOf(';', start);
      if (end == -1) end = cookie.length();
      return cookie.substring(start, end);
    }
  }
  return "";
}

bool isAuthenticated() {
  String token = getSessionToken();
  if (token.isEmpty()) return false;
  auto it = sessions.find(token);
  if (it == sessions.end()) return false;
  if (millis() - it->second.lastUsed > SESSION_TIMEOUT) {
    sessions.erase(it);
    return false;
  }
  it->second.lastUsed = millis();
  return true;
}

Session getSession() {
  Session empty = {"", "", 0, ""};
  String token = getSessionToken();
  if (token.isEmpty()) return empty;
  auto it = sessions.find(token);
  if (it == sessions.end()) return empty;
  it->second.lastUsed = millis();
  return it->second;
}

bool requireAdmin() {
  if (!isAuthenticated()) return false;
  Session s = getSession();
  return s.role == "admin";
}

bool requireUser() {
  if (!isAuthenticated()) return false;
  Session s = getSession();
  return s.role == "user";
}

bool isRateLimited(const String& ip) {
  auto it = loginAttempts.find(ip);
  if (it == loginAttempts.end()) return false;
  if (it->second.count >= MAX_LOGIN_ATTEMPTS) {
    if (millis() - it->second.firstAttempt < RATE_LIMIT_BLOCK_MS) {
      return true;
    } else {
      loginAttempts.erase(it);
    }
  }
  return false;
}

void recordFailedAttempt(const String& ip) {
  auto it = loginAttempts.find(ip);
  if (it == loginAttempts.end()) {
    loginAttempts[ip] = {1, millis()};
  } else {
    it->second.count++;
  }
}

void clearRateLimit(const String& ip) {
  loginAttempts.erase(ip);
}

// ========== CSRF Protection ==========
bool validateCSRF(const String& token) {
  Session s = getSession();
  if (s.csrfToken.isEmpty()) return false;
  return constantTimeEqual(token, s.csrfToken);
}

String getCSRFToken() {
  Session s = getSession();
  return s.csrfToken;
}

// ========== Security Headers ==========
void sendSecurityHeaders() {
  server.sendHeader("X-Content-Type-Options", "nosniff");
  server.sendHeader("X-Frame-Options", "DENY");
}

// ========== Input Validation ==========
bool isValidUsername(const String& username) {
  if (username.length() < 3 || username.length() > 20) return false;
  for (size_t i = 0; i < username.length(); i++) {
    char c = username[i];
    if (!isAlphaNumeric(c) && c != '_' && c != '.') return false;
  }
  return true;
}

bool isValidMonth(const String& month) {
  if (month.length() != 7 || month[4] != '-') return false;
  int year = month.substring(0,4).toInt();
  int mon = month.substring(5,7).toInt();
  return (year >= 2000 && year <= 2100 && mon >= 1 && mon <= 12);
}

// ========== HTML Templates ==========
String htmlHeader(const String& title) {
  return "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>" + title + "</title><style>"
         "body{font-family:Arial,sans-serif;margin:20px;background:#f4f4f4;}"
         ".container{max-width:800px;margin:auto;background:white;padding:20px;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,0.1);}"
         "h1{color:#333;}"
         "label{display:block;margin:10px 0 5px;}"
         "input[type=text],input[type=password],input[type=number],select{width:100%;padding:8px;margin-bottom:10px;border:1px solid #ccc;border-radius:4px;}"
         "input[type=submit],button{background:#4CAF50;color:white;padding:10px 15px;border:none;border-radius:4px;cursor:pointer;}"
         "input[type=submit]:hover,button:hover{background:#45a049;}"
         ".error{color:red;}.success{color:green;}"
         "table{width:100%;border-collapse:collapse;margin-top:20px;}"
         "th,td{border:1px solid #ddd;padding:8px;text-align:left;}"
         "th{background-color:#f2f2f2;}"
         ".nav{background:#333;overflow:hidden;margin-bottom:20px;}"
         ".nav a{float:left;color:white;text-align:center;padding:14px 16px;text-decoration:none;}"
         ".nav a:hover{background:#ddd;color:black;}"
         "</style></head><body><div class='container'>";
}

String htmlFooter() {
  return "</div></body></html>";
}

String loginPage(const String& error = "") {
  String page = htmlHeader("Login");
  page += "<h1>Electricity Billing System</h1>";
  if (error.length()) page += "<p class='error'>" + error + "</p>";
  page += "<form action='/login' method='POST'>";
  page += "<label>Username:</label><input type='text' name='username' required>";
  page += "<label>Password:</label><input type='password' name='password' required>";
  page += "<input type='submit' value='Login'>";
  page += "</form>";
  page += htmlFooter();
  return page;
}

// ========== Authentication Handlers ==========
void handleLoginGet() {
  sendSecurityHeaders();
  if (isAuthenticated()) {
    Session s = getSession();
    if (s.role == "admin") server.sendHeader("Location", "/admin", true);
    else server.sendHeader("Location", "/user", true);
    server.send(302, "text/plain", "");
    return;
  }
  server.send(200, "text/html", loginPage());
}

void handleLoginPost() {
  sendSecurityHeaders();
  String ip = server.client().remoteIP().toString();
  if (isRateLimited(ip)) {
    server.send(200, "text/html", loginPage("Too many attempts. Try later."));
    return;
  }

  String username = server.arg("username");
  String password = server.arg("password");

  auto it = users.find(username);
  if (it != users.end() && constantTimeEqual(strongHash(password, username), it->second.passwordHash)) {
    String token = generateToken();
    Session newSession = {username, it->second.role, millis(), generateToken()};
    sessions[token] = newSession;
    server.sendHeader("Set-Cookie", "session_token=" + token + "; Path=/; HttpOnly; SameSite=Strict");
    clearRateLimit(ip);
    if (it->second.role == "admin") {
      server.sendHeader("Location", "/admin", true);
    } else {
      server.sendHeader("Location", "/user", true);
    }
    server.send(302, "text/plain", "");
    return;
  }

  recordFailedAttempt(ip);
  server.send(200, "text/html", loginPage("Invalid username or password"));
}

void handleLogout() {
  sendSecurityHeaders();
  String token = getSessionToken();
  if (!token.isEmpty()) sessions.erase(token);
  server.sendHeader("Set-Cookie", "session_token=; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict");
  server.sendHeader("Location", "/login", true);
  server.send(302, "text/plain", "");
}

// ========== Admin Handlers ==========
void handleAdmin() {
  if (!requireAdmin()) {
    server.sendHeader("Location", "/login", true);
    server.send(302, "text/plain", "");
    return;
  }
  sendSecurityHeaders();

  String page = htmlHeader("Admin Dashboard");
  page += "<h1>Admin Panel</h1>";
  page += "<div class='nav'>";
  page += "<a href='/admin'>Dashboard</a>";
  page += "<a href='/admin/users'>Manage Users</a>";
  page += "<a href='/admin/config'>Billing Config</a>";
  page += "<a href='/admin/dashboard'>Demand Dashboard</a>";
  page += "<a href='/admin/export'>Export Data</a>";
  page += "<a href='/logout'>Logout</a>";
  page += "</div>";

  float totalUnits = 0, totalRevenue = 0;
  for (auto& r : consumptions) {
    totalUnits += r.units;
    totalRevenue += r.billAmount;
  }
  page += "<h2>System Overview</h2>";
  page += "<p>Total Users: " + String(users.size()) + "</p>";
  page += "<p>Total Units Sold: " + String(totalUnits, 2) + " kWh</p>";
  page += "<p>Total Revenue: ₹" + String(totalRevenue, 2) + "</p>";
  page += "<p>Current Price Multiplier: " + String(config.demandMultiplier, 2) + "</p>";

  page += htmlFooter();
  server.send(200, "text/html", page);
}

void handleAdminUsers() {
  if (!requireAdmin()) {
    server.sendHeader("Location", "/login", true);
    server.send(302, "text/plain", "");
    return;
  }
  sendSecurityHeaders();

  String page = htmlHeader("Manage Users");
  page += "<h1>User Management</h1>";
  page += "<div class='nav'>";
  page += "<a href='/admin'>Dashboard</a>";
  page += "<a href='/admin/users'>Users</a>";
  page += "<a href='/admin/config'>Config</a>";
  page += "<a href='/admin/dashboard'>Demand</a>";
  page += "<a href='/admin/export'>Export</a>";
  page += "<a href='/logout'>Logout</a>";
  page += "</div>";

  // Add user form
  page += "<h2>Add New User</h2>";
  page += "<form action='/admin/users' method='POST'>";
  page += "<input type='hidden' name='csrf_token' value='" + getCSRFToken() + "'>";
  page += "<label>Username:</label><input type='text' name='username' required>";
  page += "<label>Password:</label><input type='password' name='password' required>";
  page += "<label>Role:</label><select name='role'><option value='user'>User</option><option value='admin'>Admin</option></select>";
  page += "<label>Category:</label><select name='category'><option value='domestic'>Domestic</option><option value='commercial'>Commercial</option><option value='industrial'>Industrial</option></select>";
  page += "<input type='submit' value='Add User'>";
  page += "</form>";

  // User list
  page += "<h2>Existing Users</h2>";
  page += "<table border='1' cellpadding='5' cellspacing='0' style='width:100%; border-collapse:collapse;'>";
  page += "<tr><th>Username</th><th>Role</th><th>Category</th><th>Created</th><th>Actions</th></tr>";

  for (auto& p : users) {
    User& u = p.second;
    page += "<tr>";
    page += "<td>" + u.username + "</td>";
    page += "<td>" + u.role + "</td>";
    page += "<td>" + u.category + "</td>";
    page += "<td>" + String(u.createdAt / 1000) + "s</td>";

    bool isSelf = (u.username == getSession().username);
    bool isLastAdmin = (u.role == "admin" && countAdmins() <= 1);

    page += "<td>";
    if (!isSelf && !isLastAdmin) {
      page += "<a href='/admin/users/delete?username=" + u.username + "' onclick='return confirm(\"Delete?\");'>Delete</a>";
    } else {
      page += "-";
    }
    page += "</td>";
    page += "</tr>";
  }
  page += "</table>";

  page += htmlFooter();
  server.send(200, "text/html", page);
}

int countAdmins() {
  int c = 0;
  for (auto& p : users) if (p.second.role == "admin") c++;
  return c;
}

void handleAdminUsersPost() {
  if (!requireAdmin()) return;
  sendSecurityHeaders();

  if (!validateCSRF(server.arg("csrf_token"))) {
    server.send(403, "text/plain", "Invalid CSRF token");
    return;
  }

  String username = server.arg("username");
  String password = server.arg("password");
  String role = server.arg("role");
  String category = server.arg("category");
  if (category.isEmpty()) category = "domestic";

  if (!isValidUsername(username)) {
    server.send(400, "text/plain", "Invalid username (3-20 chars, alphanumeric, _ .)");
    return;
  }
  if (password.length() < 4) {
    server.send(400, "text/plain", "Password too short (min 4 chars)");
    return;
  }
  if (users.find(username) != users.end()) {
    server.send(400, "text/plain", "Username exists");
    return;
  }

  User u;
  u.id = generateId();
  u.username = username;
  u.passwordHash = strongHash(password, username);
  u.role = role;
  u.category = category;
  u.createdAt = millis();
  users[username] = u;
  saveUsers();
  server.sendHeader("Location", "/admin/users", true);
  server.send(302, "text/plain", "");
}

void handleAdminUsersDelete() {
  if (!requireAdmin()) return;
  sendSecurityHeaders();

  String username = server.arg("username");
  if (username.isEmpty()) return;
  auto it = users.find(username);
  if (it != users.end()) {
    if (it->second.role == "admin" && countAdmins() <= 1) {
      server.send(400, "text/plain", "Cannot delete the only admin");
      return;
    }
    if (username == getSession().username) {
      server.send(400, "text/plain", "Cannot delete yourself");
      return;
    }
    users.erase(it);
    saveUsers();
  }
  server.sendHeader("Location", "/admin/users", true);
  server.send(302, "text/plain", "");
}

void handleAdminConfig() {
  if (!requireAdmin()) {
    server.sendHeader("Location", "/login", true);
    server.send(302, "text/plain", "");
    return;
  }
  sendSecurityHeaders();

  String page = htmlHeader("Billing Configuration");
  page += "<h1>Configure Tariff</h1>";
  page += "<div class='nav'>";
  page += "<a href='/admin'>Dashboard</a>";
  page += "<a href='/admin/users'>Users</a>";
  page += "<a href='/admin/config'>Config</a>";
  page += "<a href='/admin/dashboard'>Demand</a>";
  page += "<a href='/admin/export'>Export</a>";
  page += "<a href='/logout'>Logout</a>";
  page += "</div>";

  page += "<form action='/admin/config' method='POST'>";
  page += "<input type='hidden' name='csrf_token' value='" + getCSRFToken() + "'>";
  page += "<h3>Slab Limits (units)</h3>";
  for (int i = 0; i < config.slabCount; i++) {
    page += "<label>Slab " + String(i+1) + " limit (units):</label><input type='number' step='1' name='limit" + String(i) + "' value='" + String(config.slabLimits[i]) + "'>";
  }
  page += "<h3>Base Rates per Category (₹/unit)</h3>";
  for (int i = 0; i < config.slabCount; i++) {
    page += "<label>Domestic Slab " + String(i+1) + ":</label><input type='number' step='0.01' name='domestic" + String(i) + "' value='" + String(config.domesticRates[i]) + "'>";
    page += "<label>Commercial Slab " + String(i+1) + ":</label><input type='number' step='0.01' name='commercial" + String(i) + "' value='" + String(config.commercialRates[i]) + "'>";
    page += "<label>Industrial Slab " + String(i+1) + ":</label><input type='number' step='0.01' name='industrial" + String(i) + "' value='" + String(config.industrialRates[i]) + "'>";
  }
  page += "<label>Fixed Charge (₹):</label><input type='number' step='0.01' name='fixedCharge' value='" + String(config.fixedCharge) + "'>";
  page += "<label>Electricity Duty (%):</label><input type='number' step='0.01' name='dutyPercent' value='" + String(config.dutyPercent) + "'>";
  page += "<label>FAC (₹/unit):</label><input type='number' step='0.01' name='facRate' value='" + String(config.facRate) + "'>";
  page += "<label>Meter Rent (₹):</label><input type='number' step='0.01' name='meterRent' value='" + String(config.meterRent) + "'>";
  page += "<input type='submit' value='Save Configuration'>";
  page += "</form>";

  page += htmlFooter();
  server.send(200, "text/html", page);
}

void handleAdminConfigPost() {
  if (!requireAdmin()) return;
  sendSecurityHeaders();

  if (!validateCSRF(server.arg("csrf_token"))) {
    server.send(403, "text/plain", "Invalid CSRF token");
    return;
  }

  // Update slab limits
  float newLimits[4];
  for (int i = 0; i < config.slabCount; i++) {
    newLimits[i] = server.arg("limit" + String(i)).toFloat();
  }
  for (int i = 1; i < config.slabCount; i++) {
    if (newLimits[i] <= newLimits[i-1]) {
      server.send(400, "text/plain", "Slab limits must be strictly increasing");
      return;
    }
  }
  for (int i = 0; i < config.slabCount; i++) {
    config.slabLimits[i] = newLimits[i];
  }

  // Update category rates
  for (int i = 0; i < config.slabCount; i++) {
    config.domesticRates[i] = server.arg("domestic" + String(i)).toFloat();
    config.commercialRates[i] = server.arg("commercial" + String(i)).toFloat();
    config.industrialRates[i] = server.arg("industrial" + String(i)).toFloat();
    if (config.domesticRates[i] < 0) config.domesticRates[i] = 0;
    if (config.commercialRates[i] < 0) config.commercialRates[i] = 0;
    if (config.industrialRates[i] < 0) config.industrialRates[i] = 0;
  }

  config.fixedCharge = server.arg("fixedCharge").toFloat();
  config.dutyPercent = server.arg("dutyPercent").toFloat();
  config.facRate = server.arg("facRate").toFloat();
  config.meterRent = server.arg("meterRent").toFloat();

  if (config.fixedCharge < 0) config.fixedCharge = 0;
  if (config.dutyPercent < 0) config.dutyPercent = 0;
  if (config.facRate < 0) config.facRate = 0;
  if (config.meterRent < 0) config.meterRent = 0;

  saveConfig();
  server.sendHeader("Location", "/admin/config", true);
  server.send(302, "text/plain", "");
}

void handleAdminDemandDashboard() {
  if (!requireAdmin()) {
    server.sendHeader("Location", "/login", true);
    server.send(302, "text/plain", "");
    return;
  }
  sendSecurityHeaders();

  // Gather demand data for last 12 months
  std::map<String, float> monthlyDemand;
  for (auto& r : consumptions) {
    String month = r.month;
    monthlyDemand[month] += r.units;
  }
  std::vector<String> months;
  for (auto& p : monthlyDemand) months.push_back(p.first);
  std::sort(months.begin(), months.end());

  String page = htmlHeader("Demand Dashboard");
  page += "<h1>Demand & Price Dashboard</h1>";
  page += "<div class='nav'>";
  page += "<a href='/admin'>Dashboard</a>";
  page += "<a href='/admin/users'>Users</a>";
  page += "<a href='/admin/config'>Config</a>";
  page += "<a href='/admin/dashboard'>Demand</a>";
  page += "<a href='/admin/export'>Export</a>";
  page += "<a href='/logout'>Logout</a>";
  page += "</div>";

  float totalUnits = 0;
  for (auto& r : consumptions) totalUnits += r.units;
  page += "<h2>Current System State</h2>";
  page += "<p>Total Demand (all time): " + String(totalUnits, 2) + " kWh</p>";
  page += "<p>Current Price Multiplier: " + String(config.demandMultiplier, 2) + "</p>";

  page += "<canvas id='demandChart' width='400' height='200'></canvas>";
  page += "<script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js'></script>";
  page += "<script>";
  page += "var months = []; var demand = [];";
  for (auto& m : months) {
    page += "months.push('" + m + "');";
    page += "demand.push(" + String(monthlyDemand[m], 2) + ");";
  }
  page += "new Chart(document.getElementById('demandChart'), { type: 'line', data: { labels: months, datasets: [{ label: 'Demand (kWh)', data: demand, borderColor: '#4CAF50', fill: false }] }, options: { responsive: true } });";
  page += "</script>";

  page += "<h3>How Demand Affects Price</h3>";
  page += "<p>Low demand ( < " + String(DEMAND_THRESHOLD_LOW) + " kWh/month) → multiplier decreases</p>";
  page += "<p>High demand ( > " + String(DEMAND_THRESHOLD_HIGH) + " kWh/month) → multiplier increases</p>";
  page += "<p>Current multiplier: " + String(config.demandMultiplier, 2) + "</p>";
  page += "<form action='/admin/update_demand' method='POST'>";
  page += "<input type='hidden' name='csrf_token' value='" + getCSRFToken() + "'>";
  page += "<input type='submit' value='Recalculate Demand Multiplier Now'>";
  page += "</form>";

  page += htmlFooter();
  server.send(200, "text/html", page);
}

void handleAdminUpdateDemand() {
  if (!requireAdmin()) return;
  sendSecurityHeaders();

  if (!validateCSRF(server.arg("csrf_token"))) {
    server.send(403, "text/plain", "Invalid CSRF token");
    return;
  }

  updateDemandMultiplier();
  server.sendHeader("Location", "/admin/dashboard", true);
  server.send(302, "text/plain", "");
}

void handleAdminExport() {
  if (!requireAdmin()) return;
  sendSecurityHeaders();

  DynamicJsonDocument doc(8192);
  JsonArray usersArr = doc.createNestedArray("users");
  for (auto& p : users) {
    User& u = p.second;
    JsonObject obj = usersArr.createNestedObject();
    obj["username"] = u.username;
    obj["role"] = u.role;
    obj["category"] = u.category;
    obj["createdAt"] = u.createdAt;
  }

  JsonObject cfgObj = doc.createNestedObject("config");
  cfgObj["fixedCharge"] = config.fixedCharge;
  cfgObj["dutyPercent"] = config.dutyPercent;
  cfgObj["facRate"] = config.facRate;
  cfgObj["meterRent"] = config.meterRent;
  cfgObj["slabCount"] = config.slabCount;
  cfgObj["demandMultiplier"] = config.demandMultiplier;
  JsonArray limits = cfgObj.createNestedArray("slabLimits");
  JsonArray domestic = cfgObj.createNestedArray("domesticRates");
  JsonArray commercial = cfgObj.createNestedArray("commercialRates");
  JsonArray industrial = cfgObj.createNestedArray("industrialRates");
  for (int i = 0; i < config.slabCount; i++) {
    limits.add(config.slabLimits[i]);
    domestic.add(config.domesticRates[i]);
    commercial.add(config.commercialRates[i]);
    industrial.add(config.industrialRates[i]);
  }

  JsonArray consumptionArr = doc.createNestedArray("consumption");
  for (auto& r : consumptions) {
    JsonObject obj = consumptionArr.createNestedObject();
    obj["userId"] = r.userId;
    obj["month"] = r.month;
    obj["units"] = r.units;
    obj["billAmount"] = r.billAmount;
    obj["energyCharges"] = r.energyCharges;
    obj["fixedCharge"] = r.fixedCharge;
    obj["dutyAmount"] = r.dutyAmount;
    obj["facAmount"] = r.facAmount;
    obj["meterRent"] = r.meterRent;
    obj["appliedMultiplier"] = r.appliedMultiplier;
    obj["timestamp"] = r.timestamp;
  }

  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "application/json", "");
  WiFiClient client = server.client();
  serializeJson(doc, client);
}

// ========== User Handlers ==========
void handleUser() {
  if (!requireUser()) {
    server.sendHeader("Location", "/login", true);
    server.send(302, "text/plain", "");
    return;
  }
  sendSecurityHeaders();

  String token = getSessionToken();
  if (!token.isEmpty() && sessions.find(token) != sessions.end() && sessions[token].csrfToken.isEmpty()) {
    sessions[token].csrfToken = generateToken();
  }

  Session s = getSession();
  User& u = users[s.username];

  std::vector<ConsumptionRecord> userRecords;
  for (auto& r : consumptions) {
    if (r.userId == u.id) userRecords.push_back(r);
  }
  std::sort(userRecords.begin(), userRecords.end(),
    [](const ConsumptionRecord& a, const ConsumptionRecord& b) { return a.month > b.month; });

  String page = htmlHeader("User Dashboard");
  page += "<h1>Welcome, " + s.username + "</h1>";
  page += "<div class='nav'>";
  page += "<a href='/user'>Dashboard</a>";
  page += "<a href='/user/history'>History</a>";
  page += "<a href='/user/export'>Export</a>";
  page += "<a href='/logout'>Logout</a>";
  page += "</div>";

  // Show current demand multiplier
  page += "<p>Current price multiplier: " + String(config.demandMultiplier, 2) + "</p>";
  page += "<p>Your category: " + u.category + "</p>";

  page += "<h2>Add Monthly Reading</h2>";
  page += "<form action='/user/add_reading' method='POST' id='readingForm'>";
  page += "<input type='hidden' name='csrf_token' value='" + getCSRFToken() + "'>";
  page += "<label>Month (YYYY-MM):</label><input type='text' name='month' placeholder='2025-03' pattern='\\d{4}-\\d{2}' required>";
  page += "<label>Units Consumed (kWh):</label><input type='number' step='0.01' name='units' min='0.01' required>";
  page += "<button type='button' onclick='previewBill()'>Preview Bill</button>";
  page += "<div id='preview'></div>";
  page += "<input type='submit' value='Save Bill'>";
  page += "</form>";

  // Analytics
  float totalUnits = 0, totalBill = 0, maxUnits = 0;
  String maxMonth = "";
  for (auto& r : userRecords) {
    totalUnits += r.units;
    totalBill += r.billAmount;
    if (r.units > maxUnits) {
      maxUnits = r.units;
      maxMonth = r.month;
    }
  }
  float avgUnits = userRecords.empty() ? 0 : totalUnits / userRecords.size();

  std::map<String, float> yearlyUnits;
  for (auto& r : userRecords) {
    String year = r.month.substring(0,4);
    yearlyUnits[year] += r.units;
  }

  page += "<h2>Summary</h2>";
  page += "<p>Total Units: " + String(totalUnits, 2) + " kWh</p>";
  page += "<p>Total Bill: ₹" + String(totalBill, 2) + "</p>";
  page += "<p>Average Monthly Units: " + String(avgUnits, 2) + " kWh</p>";
  if (!maxMonth.isEmpty()) {
    page += "<p>Highest Usage: " + String(maxUnits, 2) + " kWh in " + maxMonth + "</p>";
  }
  page += "<h3>Yearly Consumption</h3><ul>";
  for (auto& p : yearlyUnits) {
    page += "<li>" + p.first + ": " + String(p.second, 2) + " kWh</li>";
  }
  page += "</ul>";

  if (!userRecords.empty()) {
    auto& latest = userRecords[0];
    page += "<h3>Latest Bill</h3>";
    page += "<p>Month: " + latest.month + "</p>";
    page += "<p>Units: " + String(latest.units, 2) + " kWh</p>";
    page += "<p>Price Multiplier Applied: " + String(latest.appliedMultiplier, 2) + "</p>";
    page += "<p>Bill Breakdown:</p><ul>";
    page += "<li>Energy Charges: ₹" + String(latest.energyCharges, 2) + "</li>";
    page += "<li>Fixed Charge: ₹" + String(latest.fixedCharge, 2) + "</li>";
    page += "<li>Electricity Duty: ₹" + String(latest.dutyAmount, 2) + "</li>";
    page += "<li>FAC: ₹" + String(latest.facAmount, 2) + "</li>";
    page += "<li>Meter Rent: ₹" + String(latest.meterRent, 2) + "</li>";
    page += "<li><strong>Total: ₹" + String(latest.billAmount, 2) + "</strong></li>";
    page += "</ul>";
  }

  page += "<script>";
  page += "function previewBill() {";
  page += "  var month = document.querySelector('input[name=\"month\"]').value;";
  page += "  var units = document.querySelector('input[name=\"units\"]').value;";
  page += "  if(!month.match(/\\d{4}-\\d{2}/) || units <= 0) { document.getElementById('preview').innerHTML = '<p class=\"error\">Invalid input</p>'; return; }";
  page += "  var xhr = new XMLHttpRequest();";
  page += "  xhr.open('POST', '/user/preview', true);";
  page += "  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');";
  page += "  xhr.onload = function() { document.getElementById('preview').innerHTML = xhr.responseText; };";
  page += "  xhr.send('units=' + units + '&month=' + month);";
  page += "}";
  page += "</script>";

  page += htmlFooter();
  server.send(200, "text/html", page);
}

void handleUserPreview() {
  if (!requireUser()) return;
  sendSecurityHeaders();

  float units = server.arg("units").toFloat();
  if (units <= 0) {
    server.send(400, "text/plain", "Invalid units");
    return;
  }

  Session s = getSession();
  User& u = users[s.username];
  float energy, fixed, duty, fac, meter, multiplier;
  float total = calculateBill(units, config, u.category, energy, fixed, duty, fac, meter, multiplier);
  String breakdown = "<div style='margin-top:10px; background:#f9f9f9; padding:10px; border-radius:4px;'>";
  breakdown += "<strong>Bill Preview:</strong><br>";
  breakdown += "Current price multiplier: " + String(multiplier, 2) + "<br>";
  breakdown += "Energy Charges: ₹" + String(energy, 2) + "<br>";
  breakdown += "Fixed Charge: ₹" + String(fixed, 2) + "<br>";
  breakdown += "Electricity Duty: ₹" + String(duty, 2) + "<br>";
  breakdown += "FAC: ₹" + String(fac, 2) + "<br>";
  breakdown += "Meter Rent: ₹" + String(meter, 2) + "<br>";
  breakdown += "<strong>Total: ₹" + String(total, 2) + "</strong>";
  breakdown += "</div>";
  server.send(200, "text/html", breakdown);
}

void handleUserAddReading() {
  if (!requireUser()) return;
  sendSecurityHeaders();

  if (!validateCSRF(server.arg("csrf_token"))) {
    server.send(403, "text/plain", "Invalid CSRF token");
    return;
  }

  Session s = getSession();
  User& u = users[s.username];

  String month = server.arg("month");
  float units = server.arg("units").toFloat();
  if (!isValidMonth(month) || units <= 0) {
    server.send(400, "text/plain", "Invalid input");
    return;
  }

  for (auto& r : consumptions) {
    if (r.userId == u.id && r.month == month) {
      server.send(400, "text/plain", "Reading already exists for this month");
      return;
    }
  }

  // Recalculate demand multiplier before billing (real‑time adjustment)
  updateDemandMultiplier();

  float energy, fixed, duty, fac, meter, multiplier;
  float total = calculateBill(units, config, u.category, energy, fixed, duty, fac, meter, multiplier);
  ConsumptionRecord rec;
  rec.userId = u.id;
  rec.month = month;
  rec.units = units;
  rec.billAmount = total;
  rec.energyCharges = energy;
  rec.fixedCharge = fixed;
  rec.dutyAmount = duty;
  rec.facAmount = fac;
  rec.meterRent = meter;
  rec.appliedMultiplier = multiplier;
  rec.timestamp = millis();
  consumptions.push_back(rec);
  saveConsumptions();

  String page = htmlHeader("Bill Generated");
  page += "<h1>Bill for " + month + "</h1>";
  page += "<div class='nav'><a href='/user'>Back</a> | <a href='/logout'>Logout</a></div>";
  page += "<p>Units: " + String(units, 2) + " kWh</p>";
  page += "<p>Price Multiplier Applied: " + String(multiplier, 2) + "</p>";
  page += "<h3>Bill Breakdown</h3><ul>";
  page += "<li>Energy Charges: ₹" + String(energy, 2) + "</li>";
  page += "<li>Fixed Charge: ₹" + String(fixed, 2) + "</li>";
  page += "<li>Electricity Duty: ₹" + String(duty, 2) + "</li>";
  page += "<li>FAC: ₹" + String(fac, 2) + "</li>";
  page += "<li>Meter Rent: ₹" + String(meter, 2) + "</li>";
  page += "<li><strong>Total: ₹" + String(total, 2) + "</strong></li>";
  page += "</ul>";
  page += htmlFooter();
  server.send(200, "text/html", page);
}

void handleUserHistory() {
  if (!requireUser()) return;
  sendSecurityHeaders();

  Session s = getSession();
  User& u = users[s.username];

  std::vector<ConsumptionRecord> userRecords;
  for (auto& r : consumptions) {
    if (r.userId == u.id) userRecords.push_back(r);
  }
  std::sort(userRecords.begin(), userRecords.end(),
    [](const ConsumptionRecord& a, const ConsumptionRecord& b) { return a.month > b.month; });

  String page = htmlHeader("Bill History");
  page += "<h1>Your Billing History</h1>";
  page += "<div class='nav'>";
  page += "<a href='/user'>Dashboard</a>";
  page += "<a href='/user/history'>History</a>";
  page += "<a href='/user/export'>Export</a>";
  page += "<a href='/logout'>Logout</a>";
  page += "</div>";

  page += "<table border='1' cellpadding='5' cellspacing='0' style='width:100%; border-collapse:collapse;'>";
  page += "<tr><th>Month</th><th>Units (kWh)</th><th>Bill (₹)</th><th>Multiplier</th><th>Breakdown</th><th>Actions</th></tr>";

  for (auto& r : userRecords) {
    page += "<tr>";
    page += "<td>" + r.month + "</td>";
    page += "<td>" + String(r.units, 2) + "</td>";
    page += "<td>₹" + String(r.billAmount, 2) + "</td>";
    page += "<td>" + String(r.appliedMultiplier, 2) + "</td>";

    page += "<td>";
    page += "E:₹" + String(r.energyCharges,2) + "<br>";
    page += "F:₹" + String(r.fixedCharge,2) + "<br>";
    page += "D:₹" + String(r.dutyAmount,2) + "<br>";
    page += "FAC:₹" + String(r.facAmount,2) + "<br>";
    page += "R:₹" + String(r.meterRent,2);
    page += "</td>";

    page += "<td>";
    page += "<a href='/user/edit_reading?month=" + r.month + "'>Edit</a> | ";
    page += "<a href='/user/delete_reading?month=" + r.month + "' onclick='return confirm(\"Delete?\");'>Delete</a>";
    page += "</td>";

    page += "</tr>";
  }
  page += "</table>";

  // Chart for this user
  page += "<canvas id='usageChart' width='400' height='200'></canvas>";
  page += "<script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js'></script>";
  page += "<script>";
  page += "var months = []; var units = [];";
  for (auto& r : userRecords) {
    page += "months.push('" + r.month + "');";
    page += "units.push(" + String(r.units, 2) + ");";
  }
  page += "new Chart(document.getElementById('usageChart'), { type: 'bar', data: { labels: months, datasets: [{ label: 'Units (kWh)', data: units, backgroundColor: '#4CAF50' }] }, options: { responsive: true } });";
  page += "</script>";

  page += htmlFooter();
  server.send(200, "text/html", page);
}

void handleUserEditReading() {
  if (!requireUser()) return;
  sendSecurityHeaders();

  Session s = getSession();
  User& u = users[s.username];
  String month = server.arg("month");

  for (auto& r : consumptions) {
    if (r.userId == u.id && r.month == month) {
      String page = htmlHeader("Edit Reading");
      page += "<h1>Edit Reading for " + month + "</h1>";
      page += "<form action='/user/update_reading' method='POST'>";
      page += "<input type='hidden' name='csrf_token' value='" + getCSRFToken() + "'>";
      page += "<input type='hidden' name='month' value='" + month + "'>";
      page += "<label>Units:</label><input type='number' step='0.01' name='units' value='" + String(r.units, 2) + "' required>";
      page += "<input type='submit' value='Update'>";
      page += "</form>";
      page += htmlFooter();
      server.send(200, "text/html", page);
      return;
    }
  }
  server.send(404, "text/plain", "Record not found");
}

void handleUserUpdateReading() {
  if (!requireUser()) return;
  sendSecurityHeaders();

  if (!validateCSRF(server.arg("csrf_token"))) {
    server.send(403, "text/plain", "Invalid CSRF token");
    return;
  }

  Session s = getSession();
  User& u = users[s.username];
  String month = server.arg("month");
  float newUnits = server.arg("units").toFloat();
  if (newUnits <= 0) {
    server.send(400, "text/plain", "Invalid units");
    return;
  }

  for (auto& r : consumptions) {
    if (r.userId == u.id && r.month == month) {
      r.units = newUnits;
      float energy, fixed, duty, fac, meter, multiplier;
      r.billAmount = calculateBill(newUnits, config, u.category, energy, fixed, duty, fac, meter, multiplier);
      r.energyCharges = energy;
      r.fixedCharge = fixed;
      r.dutyAmount = duty;
      r.facAmount = fac;
      r.meterRent = meter;
      r.appliedMultiplier = multiplier;
      r.timestamp = millis();
      saveConsumptions();
      server.sendHeader("Location", "/user/history", true);
      server.send(302, "text/plain", "");
      return;
    }
  }
  server.send(404, "text/plain", "Record not found");
}

void handleUserDeleteReading() {
  if (!requireUser()) return;
  sendSecurityHeaders();

  Session s = getSession();
  User& u = users[s.username];
  String month = server.arg("month");

  for (auto it = consumptions.begin(); it != consumptions.end(); ++it) {
    if (it->userId == u.id && it->month == month) {
      consumptions.erase(it);
      saveConsumptions();
      break;
    }
  }
  server.sendHeader("Location", "/user/history", true);
  server.send(302, "text/plain", "");
}

void handleUserExport() {
  if (!requireUser()) return;
  sendSecurityHeaders();

  Session s = getSession();
  User& u = users[s.username];

  DynamicJsonDocument doc(8192);
  JsonArray arr = doc.createNestedArray("consumption");
  for (auto& r : consumptions) {
    if (r.userId == u.id) {
      JsonObject obj = arr.createNestedObject();
      obj["month"] = r.month;
      obj["units"] = r.units;
      obj["billAmount"] = r.billAmount;
      obj["energyCharges"] = r.energyCharges;
      obj["fixedCharge"] = r.fixedCharge;
      obj["dutyAmount"] = r.dutyAmount;
      obj["facAmount"] = r.facAmount;
      obj["meterRent"] = r.meterRent;
      obj["appliedMultiplier"] = r.appliedMultiplier;
      obj["timestamp"] = r.timestamp;
    }
  }

  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "application/json", "");
  WiFiClient client = server.client();
  serializeJson(doc, client);
}

// ========== Setup ==========
void setup() {
  Serial.begin(115200);
  if (!LittleFS.begin(true)) {
    Serial.println("LittleFS mount failed");
    return;
  }
  loadUsers();
  loadConfig();
  loadConsumptions();

  // Create default admin if none exists
  if (users.empty()) {
    User admin;
    admin.id = generateId();
    admin.username = "Haris";
    admin.passwordHash = strongHash("Asdfgh@123", admin.username);
    admin.role = "admin";
    admin.category = "domestic";
    admin.createdAt = millis();
    users[admin.username] = admin;
    saveUsers();
    Serial.println("Default admin created: Haris / Asdfgh@123");
  }

  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, netMsk);
  WiFi.softAP(AP_SSID, AP_PASS);
  Serial.println("AP Started");
  Serial.print("IP: "); Serial.println(WiFi.softAPIP());

  // Setup web routes
  server.on("/", []() {
    if (isAuthenticated()) {
      Session s = getSession();
      if (s.role == "admin") server.sendHeader("Location", "/admin", true);
      else server.sendHeader("Location", "/user", true);
      server.send(302, "text/plain", "");
    } else {
      server.sendHeader("Location", "/login", true);
      server.send(302, "text/plain", "");
    }
  });
  server.on("/login", HTTP_GET, handleLoginGet);
  server.on("/login", HTTP_POST, handleLoginPost);
  server.on("/logout", handleLogout);

  server.on("/admin", handleAdmin);
  server.on("/admin/users", HTTP_GET, handleAdminUsers);
  server.on("/admin/users", HTTP_POST, handleAdminUsersPost);
  server.on("/admin/users/delete", HTTP_GET, handleAdminUsersDelete);
  server.on("/admin/config", HTTP_GET, handleAdminConfig);
  server.on("/admin/config", HTTP_POST, handleAdminConfigPost);
  server.on("/admin/dashboard", handleAdminDemandDashboard);
  server.on("/admin/update_demand", HTTP_POST, handleAdminUpdateDemand);
  server.on("/admin/export", handleAdminExport);

  server.on("/user", handleUser);
  server.on("/user/add_reading", HTTP_POST, handleUserAddReading);
  server.on("/user/history", handleUserHistory);
  server.on("/user/edit_reading", HTTP_GET, handleUserEditReading);
  server.on("/user/update_reading", HTTP_POST, handleUserUpdateReading);
  server.on("/user/delete_reading", HTTP_GET, handleUserDeleteReading);
  server.on("/user/export", handleUserExport);
  server.on("/user/preview", HTTP_POST, handleUserPreview);

  server.onNotFound([]() {
    server.send(404, "text/plain", "Not Found");
  });

  server.begin();
  Serial.println("HTTP server started");
}

void loop() {
  server.handleClient();

  static unsigned long lastCleanup = 0;
  if (millis() - lastCleanup > 10000) {
    lastCleanup = millis();
    auto it = sessions.begin();
    while (it != sessions.end()) {
      if (millis() - it->second.lastUsed > SESSION_TIMEOUT) {
        it = sessions.erase(it);
      } else {
        ++it;
      }
    }
  }

  static unsigned long lastRateClean = 0;
  if (millis() - lastRateClean > 60000) {
    lastRateClean = millis();
    auto it = loginAttempts.begin();
    while (it != loginAttempts.end()) {
      if (millis() - it->second.firstAttempt > RATE_LIMIT_BLOCK_MS) {
        it = loginAttempts.erase(it);
      } else {
        ++it;
      }
    }
  }
}