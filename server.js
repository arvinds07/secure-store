const express = require("express");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const nodemailer = require("nodemailer");
const cloudinary = require("cloudinary").v2;
const mongoose = require("mongoose");

const app = express();

const PORT = process.env.PORT || 5000;
const SECRET = process.env.SECRET || "secret123";
const SESSION_SECRET = process.env.SESSION_SECRET || "session_secret_123";
const DB_FILE = "database.json";
const UPLOAD_DIR = "uploads";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL ||
  "http://localhost:5000/auth/google/callback";

const EMAIL_USER = process.env.EMAIL_USER || "";
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log("MongoDB Error:", err));


const EMAIL_PASS = process.env.EMAIL_PASS || "";

app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));
app.use(express.static("public"));
app.use("/uploads", express.static(UPLOAD_DIR));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({
    users: [],
    folders: [],
    otps: []
  }, null, 2));
}

function readDB() {
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function ensureDBShape(db) {
  if (!db.users) db.users = [];
  if (!db.folders) db.folders = [];
  if (!db.otps) db.otps = [];
  return db;
}

function validGmail(email) {
  return /^[a-zA-Z0-9._%+-]+@gmail\.com$/.test(String(email || "").trim().toLowerCase());
}

function makeToken(user) {
  return jwt.sign({ id: user.id }, SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  try {
    const token = req.headers.authorization || req.query.token;
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Login first" });
  }
}

function mb(bytes) {
  return (bytes / (1024 * 1024)).toFixed(2);
}

function userStorage(userId) {
  const db = ensureDBShape(readDB());
  let total = 0;

  db.folders
    .filter(folder => folder.user_id === userId)
    .forEach(folder => {
      folder.files.forEach(file => total += file.size || 0);
    });

  return total;
}

function randomOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTP(email, otp) {
  if (!EMAIL_USER || !EMAIL_PASS) {
    console.log("OTP for", email, "is", otp);
    return true;
  }

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: EMAIL_USER,
      pass: EMAIL_PASS
    }
  });

  await transporter.sendMail({
    from: `"Secure File Store" <${EMAIL_USER}>`,
    to: email,
    subject: "Secure File Store OTP",
    html: `
      <div style="font-family:Arial;padding:20px">
        <h2>Secure File Store Password Reset</h2>
        <p>Your OTP is:</p>
        <h1 style="letter-spacing:4px">${otp}</h1>
        <p>This OTP is valid for 10 minutes.</p>
      </div>
    `
  });

  return true;
}

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR + "/",
    filename: (req, file, cb) => {
      const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
      cb(null, Date.now() + "-" + safeName);
    }
  }),
  limits: {
    fileSize: 1024 * 1024 * 1024
  }
});

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser((id, done) => {
  const db = ensureDBShape(readDB());
  const user = db.users.find(u => u.id === id);
  done(null, user || false);
});

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: GOOGLE_CALLBACK_URL
  }, (accessToken, refreshToken, profile, done) => {
    const email = profile.emails?.[0]?.value || "";
    const verified = profile.emails?.[0]?.verified !== false;

    if (!validGmail(email) || !verified) {
      return done(null, false);
    }

    const db = ensureDBShape(readDB());
    let user = db.users.find(u => u.email === email);

    if (!user) {
      user = {
        id: Date.now().toString(),
        name: profile.displayName || email.split("@")[0],
        email,
        password: "",
        authType: "google",
        createdAt: new Date().toISOString()
      };
      db.users.push(user);
      writeDB(db);
    }

    return done(null, user);
  }));
}

app.get("/auth/google", (req, res, next) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res.send(`
      <h2>Google Login Not Configured</h2>
      <p>Add GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL in Render Environment.</p>
      <a href="/">Back</a>
    `);
  }

  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account"
  })(req, res, next);
});

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    const token = makeToken(req.user);
    res.send(`
      <script>
        localStorage.setItem("token", "${token}");
        window.location.href = "/";
      </script>
    `);
  }
);

app.get("/manifest.json", (req, res) => {
  res.json({
    name: "Secure File Store",
    short_name: "SecureStore",
    start_url: "/",
    display: "standalone",
    background_color: "#eef2ff",
    theme_color: "#2563eb",
    icons: [
      { src: "/logo.jpg", sizes: "192x192", type: "image/jpeg" },
      { src: "/logo.jpg", sizes: "512x512", type: "image/jpeg" }
    ]
  });
});

app.get("/sw.js", (req, res) => {
  res.type("application/javascript").send(`
    self.addEventListener("install", event => self.skipWaiting());
    self.addEventListener("activate", event => self.clients.claim());
    self.addEventListener("fetch", event => {
      event.respondWith(fetch(event.request).catch(() => caches.match(event.request)));
    });
  `);
});

app.get("/", (req, res) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
<title>Secure File Store</title>
<link rel="icon" type="image/jpeg" href="/logo.jpg">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#2563eb">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style>
*{box-sizing:border-box}
:root{--blue:#2563eb;--purple:#7c3aed;--pink:#ec4899;--green:#22c55e;--dark:#0f172a;--muted:#64748b}
body{margin:0;font-family:Arial,sans-serif;background:radial-gradient(circle at 10% 10%,#dbeafe,transparent 35%),radial-gradient(circle at 90% 0%,#f5d0fe,transparent 30%),radial-gradient(circle at 50% 90%,#dcfce7,transparent 30%),linear-gradient(135deg,#eef2ff,#fdf2f8);color:#111827;min-height:100vh}
.topbar{position:sticky;top:0;z-index:20;background:linear-gradient(90deg,var(--dark),var(--blue),var(--purple),var(--pink));color:white;padding:16px 25px;display:flex;justify-content:space-between;align-items:center;box-shadow:0 8px 24px #0002}
.brand{display:flex;align-items:center;gap:10px}
.brand img{width:42px;height:42px;border-radius:12px;background:white;object-fit:cover}
.brand h2{margin:0}
.topbar button{width:auto;padding:10px 16px;background:white;color:#111827;border-radius:999px;margin-left:8px}
.layout{display:grid;grid-template-columns:260px 1fr;gap:18px;max-width:1300px;margin:24px auto;padding:0 15px}
.auth-layout{display:block;max-width:780px}
.sidebar{position:sticky;top:86px;height:calc(100vh - 110px);background:rgba(255,255,255,.85);backdrop-filter:blur(14px);border:1px solid #fff;border-radius:24px;padding:18px;box-shadow:0 10px 30px #0001}
.side-btn{display:block;width:100%;text-align:left;margin:8px 0;padding:13px;border-radius:14px;background:#f8fafc;color:#111827;border:1px solid #e2e8f0}
.main{min-width:0}
.card{background:rgba(255,255,255,.9);backdrop-filter:blur(12px);padding:24px;margin:0 0 18px;border-radius:24px;box-shadow:0 10px 30px #1e293b18;border:1px solid #ffffffcc}
.auth-card{max-width:520px;margin:38px auto;text-align:center}
input,button{width:100%;padding:14px;margin:8px 0;border-radius:15px;border:1px solid #cbd5e1;font-size:15px}
input:focus{outline:2px solid #60a5fa;border-color:var(--blue)}
button{background:linear-gradient(90deg,var(--blue),var(--purple));color:white;border:0;cursor:pointer;font-weight:bold;transition:.15s}
button:hover{opacity:.92;transform:translateY(-1px)}
button:disabled{opacity:.55;cursor:not-allowed;transform:none}
.google-btn{background:white;color:#111827;border:1px solid #cbd5e1;box-shadow:0 5px 14px #0001}
.logo-circle{width:60px;height:60px;border-radius:20px;background:linear-gradient(135deg,var(--blue),var(--purple),var(--pink));display:flex;align-items:center;justify-content:center;color:white;font-size:26px;margin:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(185px,1fr));gap:14px}
.folder,.file{background:linear-gradient(180deg,#ffffff,#f8fafc);padding:14px;border-radius:20px;border:1px solid #e2e8f0;box-shadow:0 6px 16px #0000000e;overflow:hidden}
.folder h3,.file p{word-break:break-word}
.thumb,.video{width:100%;aspect-ratio:1/1;height:auto;object-fit:cover;border-radius:16px;background:#e2e8f0;cursor:pointer}
.video{background:#000}
.small{color:var(--muted);font-size:13px}
.hide{display:none!important}
.success{background:#dcfce7;color:#166534;padding:13px;border-radius:14px;margin:10px 0;border:1px solid #86efac}
.error{background:#fee2e2;color:#991b1b;padding:13px;border-radius:14px;margin:10px 0;border:1px solid #fca5a5}
.danger{background:linear-gradient(90deg,#dc2626,#be123c)!important;color:white!important}
.install-btn{background:linear-gradient(90deg,var(--green),#14b8a6)!important;color:white!important}
.storage{background:#e2e8f0;border-radius:20px;overflow:hidden;height:20px}
.storage div{background:linear-gradient(90deg,var(--green),var(--blue),var(--purple));height:20px;width:0%;transition:.25s}
.progress{background:#e2e8f0;border-radius:18px;height:22px;overflow:hidden;margin:10px 0}
.progress div{background:linear-gradient(90deg,var(--green),var(--blue),var(--purple));height:22px;width:0%;color:white;text-align:center;font-size:12px;line-height:22px}
.drawer-overlay{position:fixed;inset:0;background:#0007;z-index:50;display:none}
.drawer{width:25vw;min-width:310px;max-width:420px;height:100%;background:white;padding:24px;box-shadow:10px 0 40px #0003;overflow:auto}
.avatar{width:70px;height:70px;border-radius:24px;background:linear-gradient(135deg,var(--blue),var(--pink));color:white;display:flex;align-items:center;justify-content:center;font-size:32px}
.modal-overlay{position:fixed;inset:0;background:#000b;z-index:70;display:none;align-items:center;justify-content:center;padding:20px}
.modal{width:min(100%,1000px);max-height:90vh;background:white;border-radius:24px;overflow:auto;padding:18px}
.modal img,.modal video{max-width:100%;max-height:68vh;display:block;margin:auto;border-radius:18px}
@media(max-width:900px){.layout{grid-template-columns:1fr}.sidebar{position:relative;top:0;height:auto}.drawer{width:85vw}.topbar button{padding:8px 10px;font-size:13px}}
</style>
</head>
<body>

<header class="topbar">
  <div class="brand">
    <img src="/logo.jpg" onerror="this.style.display='none'">
    <h2>Secure File Store</h2>
  </div>
  <div id="topActions" class="hide">
    <button onclick="showPage('home')">Home</button>
    <button onclick="openDrawer()">Profile</button>
  </div>
</header>

<div id="appLayout" class="layout auth-layout">
  <aside id="sidebar" class="sidebar hide">
    <button class="side-btn" onclick="showPage('home')">🏠 Dashboard</button>
    <button class="side-btn" onclick="showPage('myfiles')">🖼️ My Files</button>
    <button class="side-btn" onclick="showPage('settings')">⚙️ Settings</button>
    <button class="side-btn install-btn" onclick="installApp()">📲 Install App</button>
    <button class="side-btn danger" onclick="logout()">🚪 Logout</button>
    <p class="small">Album-style photo and video view is available.</p>
  </aside>

  <main class="main">
    <div id="msg"></div>

    <section id="loginPage" class="card auth-card">
      <div class="logo-circle">🔐</div>
      <h1>Login</h1>
      <a href="/auth/google"><button class="google-btn">Continue with Google</button></a>
      <input id="lemail" placeholder="Valid Gmail">
      <input id="lpass" type="password" placeholder="Password">
      <button onclick="login()">Login</button>
      <button onclick="showAuth('register')">Create Account</button>
      <button onclick="showAuth('forgot')">Forgot Password?</button>
    </section>

    <section id="registerPage" class="card auth-card hide">
      <div class="logo-circle">✨</div>
      <h1>Register</h1>
      <a href="/auth/google"><button class="google-btn">Sign up with Google</button></a>
      <input id="rname" placeholder="Name">
      <input id="remail" placeholder="Valid Gmail only">
      <input id="rpass" type="password" placeholder="Password">
      <button onclick="register()">Register</button>
      <button onclick="showAuth('login')">Back to Login</button>
    </section>

    <section id="forgotPage" class="card auth-card hide">
      <div class="logo-circle">🔑</div>
      <h1>Forgot Password</h1>
      <input id="femail" placeholder="Registered Gmail">
      <button onclick="sendOtp()">Send OTP</button>
      <input id="fotp" placeholder="Enter OTP">
      <input id="fnewpass" type="password" placeholder="New Password">
      <button onclick="resetPassword()">Reset Password</button>
      <button onclick="showAuth('login')">Back to Login</button>
    </section>

    <section id="homePage" class="hide">
      <div class="card">
        <h2>Search Owner / Folder</h2>
        <input id="searchText" placeholder="Search owner name or folder name">
        <button onclick="searchFolder()">Search</button>
        <div id="searchResults"></div>
      </div>

      <div class="card">
        <h2>My Storage</h2>
        <p><b id="storageText">0 MB used / 1 TB</b></p>
        <div class="storage"><div id="storageBar"></div></div>
      </div>

      <div class="card">
        <h2>Create Folder</h2>
        <input id="folderName" placeholder="Folder name">
        <input id="folderPass" type="password" placeholder="Folder password">
        <button onclick="createFolder()">Create Folder</button>
      </div>

      <div class="card">
        <h2>My Folders</h2>
        <div id="myFolders" class="grid"></div>
      </div>
    </section>

    <section id="myFilesPage" class="hide">
      <div class="card">
        <h2>My Files</h2>
        <div id="allMyFiles" class="grid"></div>
      </div>
    </section>

    <section id="folderPage" class="hide">
      <div class="card">
        <button onclick="showPage('home')">Back</button>
        <h2 id="openFolderName"></h2>
        <p id="openFolderOwner" class="small"></p>

        <div id="ownerUploadBox">
          <input id="uploadFiles" type="file" multiple accept="image/*,video/*">
          <button id="uploadBtn" onclick="uploadToFolder()">Upload Images / Videos</button>
          <div id="uploadProgressWrap" class="progress hide">
            <div id="uploadProgressBar">0%</div>
          </div>
          <p id="uploadInfo" class="small"></p>
        </div>
      </div>

      <div class="card">
        <h2>Gallery View</h2>
        <div id="folderFiles" class="grid"></div>
      </div>
    </section>

    <section id="settingsPage" class="hide">
      <div class="card">
        <h2>Settings</h2>
        <p><b>Name:</b> <span id="setName"></span></p>
        <p><b>Email:</b> <span id="setEmail"></span></p>
        <p><b>Storage:</b> <span id="setStorage"></span></p>
        <button class="install-btn" onclick="installApp()">Install App</button>
      </div>
    </section>
  </main>
</div>

<div id="drawerOverlay" class="drawer-overlay" onclick="closeDrawer(event)">
  <div class="drawer">
    <div class="avatar" id="drawerAvatar">A</div>
    <h2 id="drawerName">Profile</h2>
    <p><b>Gmail:</b></p>
    <p id="drawerEmail" class="small"></p>
    <p><b>Storage:</b></p>
    <p id="drawerStorage" class="small"></p>
    <hr>
    <button onclick="showPage('settings'); closeDrawerDirect()">Settings</button>
    <button class="danger" onclick="logout()">Logout</button>
  </div>
</div>

<div id="modalOverlay" class="modal-overlay">
  <div class="modal">
    <button onclick="closeViewer()">Close</button>
    <a id="modalDownload" href="#"><button>Download</button></a>
    <h3 id="modalTitle"></h3>
    <div id="modalContent"></div>
  </div>
</div>

<script>
let token = localStorage.getItem("token");
let currentFolderId = null;
let currentUserData = null;
let deferredPrompt = null;

window.addEventListener("beforeinstallprompt", event => {
  event.preventDefault();
  deferredPrompt = event;
});

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js").catch(() => {});
}

function installApp() {
  if (deferredPrompt) {
    deferredPrompt.prompt();
    deferredPrompt.userChoice.finally(() => {
      deferredPrompt = null;
    });
  } else {
    showMsg("Use the browser menu and choose Install app / Add to Home screen.", "success");
  }
}

function showMsg(text, type = "success") {
  msg.innerHTML = '<div class="' + type + '">' + text + '</div>';
  setTimeout(() => msg.innerHTML = "", 3500);
}

function hideAllPages() {
  [loginPage, registerPage, forgotPage, homePage, myFilesPage, folderPage, settingsPage]
    .forEach(page => page.classList.add("hide"));
}

function setLoggedUI(isLogged) {
  if (isLogged) {
    sidebar.classList.remove("hide");
    topActions.classList.remove("hide");
    appLayout.classList.remove("auth-layout");
  } else {
    sidebar.classList.add("hide");
    topActions.classList.add("hide");
    appLayout.classList.add("auth-layout");
  }
}

function showAuth(page) {
  token = localStorage.getItem("token");
  setLoggedUI(false);
  hideAllPages();

  if (page === "login") loginPage.classList.remove("hide");
  if (page === "register") registerPage.classList.remove("hide");
  if (page === "forgot") forgotPage.classList.remove("hide");
}

function showPage(page) {
  token = localStorage.getItem("token");
  hideAllPages();

  if (!token) {
    showAuth("login");
    return;
  }

  setLoggedUI(true);

  if (page === "home") {
    homePage.classList.remove("hide");
    loadDashboard();
  }

  if (page === "myfiles") {
    myFilesPage.classList.remove("hide");
    loadMyFiles();
  }

  if (page === "folder") {
    folderPage.classList.remove("hide");
  }

  if (page === "settings") {
    settingsPage.classList.remove("hide");
    loadSettings();
  }
}

function validGmail(email) {
  return /^[a-zA-Z0-9._%+-]+@gmail\\.com$/.test(String(email || "").trim().toLowerCase());
}

async function register() {
  const email = remail.value.trim().toLowerCase();

  if (!validGmail(email)) {
    return showMsg("Only a valid Gmail address is allowed. Example: name@gmail.com", "error");
  }

  const response = await fetch("/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: rname.value.trim(),
      email,
      password: rpass.value
    })
  });

  const data = await response.json();

  if (data.error) return showMsg(data.error, "error");

  showMsg("Register successful. Login now.", "success");
  showAuth("login");
}

async function login() {
  const email = lemail.value.trim().toLowerCase();

  if (!validGmail(email)) {
    return showMsg("Enter a valid Gmail address", "error");
  }

  const response = await fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email,
      password: lpass.value
    })
  });

  const data = await response.json();

  if (data.token) {
    token = data.token;
    localStorage.setItem("token", token);
    showMsg("Login successful", "success");
    showPage("home");
  } else {
    showMsg(data.error || "Login failed", "error");
  }
}

async function sendOtp() {
  const email = femail.value.trim().toLowerCase();

  if (!validGmail(email)) {
    return showMsg("Enter a valid Gmail address", "error");
  }

  const response = await fetch("/forgot/send-otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email })
  });

  const data = await response.json();

  if (data.error) return showMsg(data.error, "error");

  showMsg("OTP sent. If email does not arrive, check Render Logs or local terminal for OTP.", "success");
}

async function resetPassword() {
  const response = await fetch("/forgot/reset", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: femail.value.trim().toLowerCase(),
      otp: fotp.value.trim(),
      newPassword: fnewpass.value
    })
  });

  const data = await response.json();

  if (data.error) return showMsg(data.error, "error");

  showMsg("Password reset successful. Login now.", "success");
  showAuth("login");
}

function logout() {
  localStorage.removeItem("token");
  token = null;
  currentFolderId = null;
  currentUserData = null;
  showMsg("Logout successful", "success");
  showAuth("login");
}

async function loadDashboard() {
  const response = await fetch("/dashboard", {
    headers: { Authorization: token }
  });

  const data = await response.json();

  if (data.error) {
    logout();
    return;
  }

  currentUserData = data;
  updateProfileUI();

  storageText.innerText = data.storageMB + " MB used / 1 TB";
  storageBar.style.width = data.storagePercent + "%";

  myFolders.innerHTML = "";

  if (data.folders.length === 0) {
    myFolders.innerHTML = "<p>No folders created.</p>";
  }

  data.folders.forEach(folder => {
    myFolders.innerHTML += '<div class="folder"><h3>📁 ' + folder.name + '</h3><p class="small">' + folder.filesCount + ' files</p><button onclick="openFolder(\\'' + folder.id + '\\')">View / Open</button><button class="danger" onclick="deleteFolder(\\'' + folder.id + '\\')">Delete</button></div>';
  });
}

function updateProfileUI() {
  if (!currentUserData) return;

  drawerName.innerText = currentUserData.name || "User";
  drawerEmail.innerText = currentUserData.email || "";
  drawerStorage.innerText = currentUserData.storageMB + " MB / 1 TB";
  drawerAvatar.innerText = (currentUserData.name || "U")[0].toUpperCase();
}

function openDrawer() {
  if (!token) {
    showAuth("login");
    return;
  }

  updateProfileUI();
  drawerOverlay.style.display = "block";
}

function closeDrawer(event) {
  if (event.target.id === "drawerOverlay") {
    drawerOverlay.style.display = "none";
  }
}

function closeDrawerDirect() {
  drawerOverlay.style.display = "none";
}

async function loadSettings() {
  const response = await fetch("/settings", {
    headers: { Authorization: token }
  });

  const data = await response.json();

  if (data.error) {
    logout();
    return;
  }

  setName.innerText = data.name;
  setEmail.innerText = data.email;
  setStorage.innerText = data.storageMB + " MB / 1 TB";
}

async function createFolder() {
  if (!folderName.value || !folderPass.value) {
    return showMsg("Enter folder name and password", "error");
  }

  const response = await fetch("/folder/create", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: token
    },
    body: JSON.stringify({
      name: folderName.value,
      password: folderPass.value
    })
  });

  const data = await response.json();

  if (data.error) return showMsg(data.error, "error");

  folderName.value = "";
  folderPass.value = "";
  showMsg("Folder created successfully", "success");
  loadDashboard();
}

async function searchFolder() {
  const response = await fetch("/search?q=" + encodeURIComponent(searchText.value), {
    headers: { Authorization: token }
  });

  const data = await response.json();
  searchResults.innerHTML = "";

  if (data.length === 0) {
    searchResults.innerHTML = "<p>No result found.</p>";
    return;
  }

  data.forEach(folder => {
    if (folder.isOwner) {
      searchResults.innerHTML += '<div class="folder"><h3>📁 ' + folder.name + '</h3><p class="small">Owner: ' + folder.owner + '</p><p class="small">' + folder.filesCount + ' files</p><button onclick="openFolder(\\'' + folder.id + '\\')">Open My Folder</button></div>';
    } else {
      searchResults.innerHTML += '<div class="folder"><h3>📁 ' + folder.name + '</h3><p class="small">Owner: ' + folder.owner + '</p><p class="small">' + folder.filesCount + ' files</p><input id="pass_' + folder.id + '" type="password" placeholder="Folder password"><button onclick="unlockFolder(\\'' + folder.id + '\\')">View Folder</button></div>';
    }
  });
}

async function unlockFolder(id) {
  const pass = document.getElementById("pass_" + id).value;

  const response = await fetch("/folder/" + id + "/unlock", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: token
    },
    body: JSON.stringify({ password: pass })
  });

  const data = await response.json();

  if (data.error) {
    return showMsg("Wrong folder password", "error");
  }

  showMsg("Folder opened successfully", "success");
  openFolder(id);
}

async function openFolder(id) {
  currentFolderId = id;

  const response = await fetch("/folder/" + id, {
    headers: { Authorization: token }
  });

  const data = await response.json();

  if (data.error) {
    return showMsg(data.error, "error");
  }

  showPage("folder");

  openFolderName.innerText = "📁 " + data.name;
  openFolderOwner.innerText = "Owner: " + data.owner;

  if (data.isOwner) {
    ownerUploadBox.classList.remove("hide");
  } else {
    ownerUploadBox.classList.add("hide");
  }

  renderFiles(data.files, data.id, folderFiles);
}

function safeText(text) {
  return String(text || "").replace(/'/g, "").replace(/"/g, "");
}

function getFileUrl(file) {
  if (String(file.filename || "").startsWith("http")) {
    return file.filename;
  }
  return "/uploads/" + file.filename;
}

function renderFiles(files, folderId, target) {
  target.innerHTML = "";

  if (files.length === 0) {
    target.innerHTML = "<p>No files uploaded.</p>";
    return;
  }

  files.forEach(file => {
    const realFolderId = file.folderId || folderId;
    const fileUrl = getFileUrl(file);
    let preview = "";

    if (file.type.startsWith("image/")) {
      preview =
        '<img class="thumb" onclick="viewFile(\\'' +
        realFolderId + '\\',\\'' +
        file.id + '\\',\\'' +
        safeText(file.originalname) + '\\',\\'' +
        file.type + '\\',\\'' +
        encodeURIComponent(fileUrl) +
        '\\')" src="' + fileUrl + '">';
    } else if (file.type.startsWith("video/")) {
      preview =
        '<video class="video" onclick="viewFile(\\'' +
        realFolderId + '\\',\\'' +
        file.id + '\\',\\'' +
        safeText(file.originalname) + '\\',\\'' +
        file.type + '\\',\\'' +
        encodeURIComponent(fileUrl) +
        '\\')" src="' + fileUrl + '"></video>';
    } else {
      preview = '<div class="thumb" style="display:flex;align-items:center;justify-content:center">File</div>';
    }

    target.innerHTML +=
      '<div class="file">' +
      preview +
      '<p><b>' + file.originalname + '</b></p>' +
      '<p class="small">' + file.sizeMB + ' MB</p>' +
      '<button onclick="viewFile(\\'' + realFolderId + '\\',\\'' + file.id + '\\',\\'' + safeText(file.originalname) + '\\',\\'' + file.type + '\\',\\'' + encodeURIComponent(fileUrl) + '\\')">View</button>' +
      '<a href="/download/' + realFolderId + '/' + file.id + '?token=' + encodeURIComponent(token) + '"><button>Download</button></a>' +
      '</div>';
  });
}

function viewFile(folderId, fileId, name, type, encodedUrl) {
  const fileUrl = decodeURIComponent(encodedUrl);

  modalTitle.innerText = name;
  modalDownload.href = "/download/" + folderId + "/" + fileId + "?token=" + encodeURIComponent(token);

  if (type.startsWith("image/")) {
    modalContent.innerHTML = '<img src="' + fileUrl + '">';
  } else if (type.startsWith("video/")) {
    modalContent.innerHTML = '<video controls autoplay src="' + fileUrl + '"></video>';
  } else {
    modalContent.innerHTML = "<p>Preview not available.</p>";
  }

  modalOverlay.style.display = "flex";
}

function closeViewer() {
  modalOverlay.style.display = "none";
  modalContent.innerHTML = "";
}

async function uploadToFolder() {
  if (!currentFolderId) return showMsg("Open folder first", "error");
  if (uploadFiles.files.length === 0) return showMsg("Select image/video", "error");

  uploadBtn.disabled = true;
  uploadBtn.innerText = "Uploading...";
  uploadProgressWrap.classList.remove("hide");
  uploadProgressBar.style.width = "0%";
  uploadProgressBar.innerText = "0%";

  let totalSize = 0;
  for (const file of uploadFiles.files) totalSize += file.size;
  uploadInfo.innerText = "Selected size: " + (totalSize / (1024 * 1024)).toFixed(2) + " MB";

  const formData = new FormData();
  for (const file of uploadFiles.files) formData.append("files", file);

  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/folder/" + currentFolderId + "/upload");
  xhr.setRequestHeader("Authorization", token);

  xhr.upload.onprogress = event => {
    if (event.lengthComputable) {
      const percent = Math.round((event.loaded / event.total) * 100);
      uploadProgressBar.style.width = percent + "%";
      uploadProgressBar.innerText = percent + "%";
    }
  };

  xhr.onload = () => {
    uploadBtn.disabled = false;
    uploadBtn.innerText = "Upload Images / Videos";

    try {
      const data = JSON.parse(xhr.responseText);
      if (data.error) return showMsg(data.error, "error");

      showMsg("Files uploaded successfully", "success");
      uploadFiles.value = "";
      uploadInfo.innerText = "";
      openFolder(currentFolderId);
      loadDashboard();
    } catch {
      showMsg("Upload failed", "error");
    }
  };

  xhr.onerror = () => {
    uploadBtn.disabled = false;
    uploadBtn.innerText = "Upload Images / Videos";
    showMsg("Upload failed. Network issue.", "error");
  };

  xhr.send(formData);
}

async function deleteFolder(id) {
  if (!confirm("Delete this folder?")) return;

  const response = await fetch("/folder/" + id + "/delete", {
    method: "DELETE",
    headers: { Authorization: token }
  });

  const data = await response.json();

  if (data.error) return showMsg(data.error, "error");

  showMsg("Folder deleted successfully", "success");
  loadDashboard();
}

async function loadMyFiles() {
  const response = await fetch("/my-files", {
    headers: { Authorization: token }
  });

  const data = await response.json();

  if (data.error) return showMsg(data.error, "error");

  renderFiles(data.files, "myfiles", allMyFiles);
}

if (token) {
  showPage("home");
} else {
  showAuth("login");
}
</script>

</body>
</html>`);
});

app.post("/register", async (req, res) => {
  const db = ensureDBShape(readDB());
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = req.body.password;

  if (!name || !email || !password) {
    return res.json({ error: "All fields required" });
  }

  if (!validGmail(email)) {
    return res.json({ error: "Only a valid Gmail address is allowed. Example: name@gmail.com" });
  }

  if (db.users.find(u => u.email === email)) {
    return res.json({ error: "Email already exists" });
  }

  db.users.push({
    id: Date.now().toString(),
    name,
    email,
    password: await bcrypt.hash(password, 10),
    authType: "local",
    createdAt: new Date().toISOString()
  });

  writeDB(db);
  res.json({ message: "Register success" });
});

app.post("/login", async (req, res) => {
  const db = ensureDBShape(readDB());
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = req.body.password;

  if (!validGmail(email)) {
    return res.json({ error: "Enter a valid Gmail address" });
  }

  const user = db.users.find(u => u.email === email);
  if (!user) return res.json({ error: "User not found" });

  if (!user.password) {
    return res.json({ error: "This account uses Google login" });
  }

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.json({ error: "Wrong password" });

  res.json({ token: makeToken(user) });
});

app.post("/forgot/send-otp", async (req, res) => {
  const db = ensureDBShape(readDB());
  const email = String(req.body.email || "").trim().toLowerCase();

  if (!validGmail(email)) {
    return res.json({ error: "Enter a valid Gmail address" });
  }

  const user = db.users.find(u => u.email === email);
  if (!user) return res.json({ error: "Email not registered" });

  if (!user.password) {
    return res.json({ error: "Google login account cannot reset password here" });
  }

  const otp = randomOTP();
  db.otps = db.otps.filter(o => o.email !== email);
  db.otps.push({
    email,
    otp,
    expiresAt: Date.now() + 10 * 60 * 1000
  });

  writeDB(db);

  try {
    await sendOTP(email, otp);
    res.json({ message: "OTP sent" });
  } catch (err) {
    console.log(err);
    res.json({ error: "OTP email failed. Check EMAIL_USER and EMAIL_PASS" });
  }
});

app.post("/forgot/reset", async (req, res) => {
  const db = ensureDBShape(readDB());
  const email = String(req.body.email || "").trim().toLowerCase();
  const otp = String(req.body.otp || "").trim();
  const newPassword = req.body.newPassword;

  if (!email || !otp || !newPassword) {
    return res.json({ error: "All fields required" });
  }

  const record = db.otps.find(o => o.email === email && o.otp === otp);
  if (!record) return res.json({ error: "Invalid OTP" });
  if (Date.now() > record.expiresAt) return res.json({ error: "OTP expired" });

  const user = db.users.find(u => u.email === email);
  if (!user) return res.json({ error: "User not found" });

  user.password = await bcrypt.hash(newPassword, 10);
  db.otps = db.otps.filter(o => o.email !== email);

  writeDB(db);
  res.json({ message: "Password reset success" });
});

app.get("/dashboard", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const user = db.users.find(u => u.id === req.user.id);

  if (!user) return res.json({ error: "User not found" });

  const used = userStorage(user.id);
  const oneTB = 1024 * 1024 * 1024 * 1024;

  const folders = db.folders
    .filter(f => f.user_id === user.id)
    .map(f => ({
      id: f.id,
      name: f.name,
      filesCount: f.files.length
    }));

  res.json({
    name: user.name,
    email: user.email,
    storageMB: mb(used),
    storagePercent: Math.min((used / oneTB) * 100, 100),
    folders
  });
});

app.get("/settings", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const user = db.users.find(u => u.id === req.user.id);

  if (!user) return res.json({ error: "User not found" });

  res.json({
    name: user.name,
    email: user.email,
    storageMB: mb(userStorage(user.id))
  });
});

app.get("/my-files", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const files = [];

  db.folders
    .filter(folder => folder.user_id === req.user.id)
    .forEach(folder => {
      folder.files.forEach(file => {
        files.push({
          ...file,
          folderId: folder.id,
          sizeMB: mb(file.size)
        });
      });
    });

  res.json({ files });
});

app.post("/folder/create", auth, async (req, res) => {
  const db = ensureDBShape(readDB());
  const name = String(req.body.name || "").trim();
  const password = req.body.password;

  if (!name || !password) {
    return res.json({ error: "Folder name and password required" });
  }

  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.json({ error: "User not found" });

  db.folders.push({
    id: Date.now().toString(),
    user_id: user.id,
    owner: user.name,
    name,
    password: await bcrypt.hash(password, 10),
    files: [],
    unlockedUsers: [],
    createdAt: new Date().toISOString()
  });

  writeDB(db);
  res.json({ message: "Folder created" });
});

app.get("/search", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const q = String(req.query.q || "").toLowerCase();

  const folders = db.folders
    .filter(f =>
      f.name.toLowerCase().includes(q) ||
      f.owner.toLowerCase().includes(q)
    )
    .map(f => ({
      id: f.id,
      name: f.name,
      owner: f.owner,
      filesCount: f.files.length,
      isOwner: f.user_id === req.user.id
    }));

  res.json(folders);
});

app.post("/folder/:id/unlock", auth, async (req, res) => {
  const db = ensureDBShape(readDB());
  const folder = db.folders.find(f => f.id === req.params.id);

  if (!folder) return res.json({ error: "Folder not found" });

  if (folder.user_id === req.user.id) {
    return res.json({ message: "Owner access" });
  }

  const ok = await bcrypt.compare(req.body.password || "", folder.password);
  if (!ok) return res.status(403).json({ error: "Wrong folder password" });

  if (!folder.unlockedUsers.includes(req.user.id)) {
    folder.unlockedUsers.push(req.user.id);
  }

  writeDB(db);
  res.json({ message: "Folder unlocked" });
});

app.get("/folder/:id", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const folder = db.folders.find(f => f.id === req.params.id);

  if (!folder) return res.json({ error: "Folder not found" });

  const isOwner = folder.user_id === req.user.id;
  const unlocked = folder.unlockedUsers.includes(req.user.id);

  if (!isOwner && !unlocked) {
    return res.status(403).json({ error: "Enter folder password first" });
  }

  res.json({
    id: folder.id,
    name: folder.name,
    owner: folder.owner,
    isOwner,
    files: folder.files.map(file => ({
      id: file.id,
      originalname: file.originalname,
      filename: file.filename,
      type: file.type,
      sizeMB: mb(file.size)
    }))
  });
});

app.post("/folder/:id/upload", auth, upload.array("files", 100), async (req, res) => {
  const db = ensureDBShape(readDB());
  const folder = db.folders.find(f => f.id === req.params.id);

  if (!folder) return res.json({ error: "Folder not found" });

  if (folder.user_id !== req.user.id) {
    return res.status(403).json({ error: "Only owner can upload" });
  }

  try {
    for (const file of req.files) {
      const result = await cloudinary.uploader.upload(file.path, {
        resource_type: "auto",
        folder: "secure-store"
      });

      folder.files.push({
        id: Date.now().toString() + Math.random().toString(16).slice(2),
        originalname: file.originalname,
        filename: result.secure_url,
        cloudinaryId: result.public_id,
        type: file.mimetype,
        size: file.size,
        uploadedAt: new Date().toISOString()
      });

      fs.unlinkSync(file.path);
    }

    writeDB(db);
    res.json({ message: "Files uploaded" });
  } catch (err) {
    console.log(err);
    res.json({ error: "Cloudinary upload failed" });
  }
});

function findFileAccess(db, folderId, fileId, userId) {
  let folder;

  if (folderId === "myfiles") {
    folder = db.folders.find(f =>
      f.user_id === userId &&
      f.files.some(file => file.id === fileId)
    );
  } else {
    folder = db.folders.find(f => f.id === folderId);
  }

  if (!folder) return { error: "Folder not found" };

  const isOwner = folder.user_id === userId;
  const unlocked = folder.unlockedUsers.includes(userId);

  if (!isOwner && !unlocked) return { error: "Folder locked" };

  const file = folder.files.find(f => f.id === fileId);
  if (!file) return { error: "File not found" };

  return { folder, file };
}

app.get("/download/:folderId/:fileId", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const result = findFileAccess(db, req.params.folderId, req.params.fileId, req.user.id);

  if (result.error) return res.status(403).send(result.error);

  if (String(result.file.filename || "").startsWith("http")) {
  return res.redirect(
    result.file.filename.replace("/upload/", "/upload/fl_attachment/")
  );
}

  const filePath = path.join(__dirname, UPLOAD_DIR, result.file.filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).send("Uploaded file missing");
  }

  res.download(filePath, result.file.originalname);
});

app.delete("/folder/:id/delete", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const folder = db.folders.find(f => f.id === req.params.id);

  if (!folder) return res.json({ error: "Folder not found" });

  if (folder.user_id !== req.user.id) {
    return res.status(403).json({ error: "Only owner can delete" });
  }

  folder.files.forEach(file => {
    const filePath = path.join(__dirname, UPLOAD_DIR, file.filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  });

  db.folders = db.folders.filter(f => f.id !== folder.id);

  writeDB(db);
  res.json({ message: "Folder deleted" });
});

app.listen(PORT, () => {
  console.log("Website running: http://localhost:" + PORT);
});
