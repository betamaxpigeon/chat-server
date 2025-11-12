const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { Server } = require("socket.io");
const { hashPassword, verifyPassword } = require("./auth");

const APP_ROOT = __dirname;
const USERS_FILE = path.join(APP_ROOT, "users.json");

function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  } catch (e) {
    console.error("Failed to parse users.json:", e);
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

let users = loadUsers();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(APP_ROOT, "public")));

function findUser(username) {
  return users.find(u => u.username === username);
}

app.post("/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const action = req.body.action || "login";

  if (!username) return res.status(400).json({ error: "username required" });

  let user = findUser(username);

  if (action === "register") {
    if (user) return res.status(400).json({ error: "username already exists" });
    if (!password) return res.status(400).json({ error: "password required to register" });

    try {
      const hashed = await hashPassword(password);
      user = { username, role: "user", password: hashed };
      users.push(user);
      saveUsers(users);
      res.cookie("username", username, { httpOnly: false });
      return res.json({ ok: true, username, role: user.role });
    } catch (e) {
      console.error("registration error:", e);
      return res.status(500).json({ error: "registration failed" });
    }
  } else {
    if (!user) return res.status(400).json({ error: "user not found" });
    if (!user.password) return res.status(400).json({ error: "user has no password set" });

    try {
      const ok = await verifyPassword(password, user.password);
      if (!ok) return res.status(401).json({ error: "invalid credentials" });
      res.cookie("username", username, { httpOnly: false });
      return res.json({ ok: true, username, role: user.role });
    } catch (e) {
      console.error("login error:", e);
      return res.status(500).json({ error: "login failed" });
    }
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("username");
  res.json({ ok: true });
});

function requireLogin(req, res, next) {
  const username = req.cookies.username;
  if (!username) return res.redirect("/login");
  const user = findUser(username);
  if (!user) return res.redirect("/login");
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const username = req.cookies.username;
  if (!username) return res.redirect("/login");
  const user = findUser(username);
  if (!user || user.role !== "admin") return res.status(403).send("Access denied");
  req.user = user;
  next();
}

app.get("/chat", requireLogin, (req, res) => {
  res.sendFile(path.join(APP_ROOT, "public", "chat.html"));
});
app.get("/admin", requireAdmin, (req, res) => {
  res.sendFile(path.join(APP_ROOT, "public", "admin.html"));
});
app.get("/view", (req, res) => {
  res.sendFile(path.join(APP_ROOT, "public", "view.html"));
});
app.get("/login", (req, res) => {
  res.sendFile(path.join(APP_ROOT, "public", "login.html"));
});


app.get("/api/users", requireAdmin, (req, res) => {
  res.json(users.map(u => ({ username: u.username, role: u.role, hasPassword: !!u.password, created: u.created || null })));
});

app.post("/api/user/set-role", requireAdmin, (req, res) => {
  const { username, role } = req.body;
  const u = findUser(username);
  if (!u) return res.status(404).json({ error: "not found" });
  u.role = role;
  saveUsers(users);
  res.json({ ok: true });
});

app.post("/api/user/set-password", requireAdmin, async (req, res) => {
  const { username, password } = req.body;
  const u = findUser(username);
  if (!u) return res.status(404).json({ error: "not found" });
  try {
    u.password = await hashPassword(password);
    saveUsers(users);
    res.json({ ok: true });
  } catch (e) {
    console.error("set-password error:", e);
    res.status(500).json({ error: "failed" });
  }
});

let messages = [];

io.on("connection", (socket) => {
  const cookie = socket.handshake.headers.cookie || "";
  const match = cookie.match(/username=([^;]+)/);
  const username = match ? decodeURIComponent(match[1]) : "anon";
  const userRecord = findUser(username);
  const displayName = userRecord ? userRecord.username : "anon";

  console.log("socket connected:", socket.id, "as", displayName);
  socket.emit("history", messages);

  socket.on("message", (text) => {
    const msg = { user: displayName, text: String(text).slice(0, 2000), ts: Date.now() };
    messages.push(msg);
    if (messages.length > 200) messages.shift();
    io.emit("message", msg);
  });

  socket.on("disconnect", () => {
    console.log("socket disconnected:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;
const LOCATION = `localhost:${PORT}`;
server.listen(PORT, () => {
  console.log(`chat server with accounts running at http://${LOCATION}`);
});
