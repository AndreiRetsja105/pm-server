// --- server.js (ESM) ---
import express from "express";  /// 
import cors from "cors";  ////
import fs from "fs-extra"; //
import { fileURLToPath } from "node:url";  ///
import path from "node:path"; ///
import crypto from "node:crypto";  /// / Cryptographic utilities (random bytes, UUID,and etc.) 
import nodemailer from "nodemailer";   ////
import rateLimit from "express-rate-limit";   ///  
import validator from "validator";  ///  Validatio and sanitization helpers 
import helmet from "helmet";   ////  sets secure Http headers  
import dotenv from "dotenv";
dotenv.config();

// helpers
const strip = (s) => String(s || "").replace(/\/+$/, "");

// where your API is publicly reachable (used in email link)
const APP_BASE_URL = strip(
  process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3000}`
);

// where users should land after activation (your GitHub Pages site)
const FRONTEND_URL = strip(
  process.env.FRONTEND_URL ||
  "https://andreiretsja105.github.io/API-computer-parts-database-and-secure-storage"
);

//// paths bootstrap /////////////
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();  ////  Loading  .env 

////////////  Configurations ////////////////////////////////

const NODE_ENV = process.env.NODE_ENV || "development";    
const PORT = Number(process.env.PORT || 3000);   /// checking the port server 

const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || "http://127.0.0.1:5500,https://andreiretsja105.github.io")
  .split(",")       /// split the commas 
  .map((s) => s.trim())   /// trimming if there any white spaces
  .filter(Boolean);     /// remove strings if empty 


////// storage locations ////////////////////////
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname);  /// directory path of data
const DB_PATH = path.join(DATA_DIR, "db.json");    /// DataBase  of Json file 
 /// const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;   ////the public base of URl, used for the backend
const TOKEN_TTL_HOURS = Number(process.env.TOKEN_TTL_HOURS || 24);  /// life time of the activation token 
const EMAIL_FROM = process.env.EMAIL_FROM || "Secure App <no-reply@example.com>";   /// default email 
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || "";    /// Admin Api key for protection  
const ARCHIVE_EMAIL = process.env.ARCHIVE_EMAIL || "";    /// Archive mailbox ,it will be used in the future , at the moment it is not connected.

// Ensure if data folders exist in the server side
const baseDir = path.join(__dirname, 'files');  /// it is create the folder files if not exist 
fs.ensureDirSync(path.join(baseDir, 'users'));   /// it is create the folder users inside the folder files  if not exist 
fs.ensureDirSync(path.join(baseDir, 'vaults'));   /// it is create the folder vaults inside the folder files  if not exist 


////////////////App & Security -------------------

const app = express();  /// create express App instance 
app.set("trust proxy", 1); ///  Trust first proxy (using for  Render server hosting)
app.use(helmet());  ////  use secure Http headers
app.use(express.json({ limit: "100mb" })); /// Parse Json with the Limit


/////////////CORS (allow list + preflight) ----

const corsOptions = {
  origin(origin, cb) {
    if (!origin) return cb(null, true); /// Allowing send requests with no Origin (curl/Postman/same-origin) 
    const ok = FRONTEND_ORIGINS.includes(strip(origin.toLowerCase())); // Check origin against allow-list
    cb(ok ? null : new Error(`CORS: ${origin} not allowed`), ok); // It will approve or reject 
  },
  methods: ["GET", "POST", "DELETE", "OPTIONS"],  /// which methods is allowed HTTP
  allowedHeaders: ["Content-Type", "Authorization", "x-admin-key"],   /// which headers is allowed
  credentials: false,  //// do not allow credentials by default
  optionsSuccessStatus: 204,  ///  response if successful
};
app.use(cors(corsOptions)); // Enable Cors for using routes 
app.options("*", cors(corsOptions));   // handle preflight requests

// Rate limits
const registerLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });  // Limit register attempts
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });  // Limit login attempts

// /////////////////// DB utils -----------------------

await fs.ensureDir(DATA_DIR);  ///  ensure at data Directory is exists
async function loadDB() {    /// read Json dataBase with defaults if it's it
  try {
    const json = await fs.readJson(DB_PATH);  /// Load Json from disk
    return { users: json.users ?? {}, vaults: json.vaults ?? {} };  //// provide defaults
  } catch {
    return { users: {}, vaults: {} };  //// when is run or after error read , start as empty 
  }
}
async function saveDB(db) {  /// save Json dataBase to the disk 
  await fs.writeJson(DB_PATH, db, { spaces: 2 });   ///  Json print 
}


///////////////////////// Helpers -------------------------

const genToken = (bytes = 32) => crypto.randomBytes(bytes).toString("hex");  /// generate token 
const hoursFromNow = (h) => new Date(Date.now() + h * 3600 * 1000).toISOString();    ////  time stamp ISo 
const lower = (s) => String(s || "").toLowerCase();   /// lowercase helper 


///////////// Authentification middleware  ------------------------

function requireAdmin(req, res, next) {    /// Api key protect Admin endpoints
  const key = req.header("x-admin-key");   //// admin key  headar
  if (!key || key !== ADMIN_API_KEY) {   ///// validation key of Admin 
    return res.status(401).json({ error: "Unauthorized" });  ///// erorr id Admin key is not proside 
  }
  next();   /// procide to hadler 
}

////////////////////////// Mail transports --------------------

// 1) Mailtrap (SMTP) it's workin just as a test version 
/// in Mailtrap admin can see who and when was try to register.
/// Also form Mailtrap admin can verified user.

let trapTransport = null;   /// transport copy inbox
if (process.env.SMTP_USER && process.env.SMTP_PASS) {  ///// Only configure if credentials provided
  const host = process.env.SMTP_HOST || "sandbox.smtp.mailtrap.io";   ////Smtp host 
  const port = Number(process.env.SMTP_PORT || 2525);  /// port Smtp
  trapTransport = nodemailer.createTransport({   ///// Create the Smtp transport
    host, 
    port,
    secure: false,  /// use start Tls if available 
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },  /// Smpt Authentification 
    connectionTimeout: 10000,  //// Timeout  connection  
    greetingTimeout: 7000,    
    socketTimeout: 15000,
  });
  try {
    await trapTransport.verify();  //// Connetction verified ////Smpt 
    console.log(`Mailtrap SMTP: OK (${host}:${port})`);  //// Success 
  } catch (e) {      ///  if 
    console.warn("Mailtrap SMTP verify failed ->", e.message);  //// worn on failure 
    trapTransport = null;  /// disable transport on failure 
  }
} else {
  console.log("Mailtrap SMTP not configured (no copy inbox).");   //// if not congure it should inform 
}

///// 2) Sendgrid. It is a real user delivery mail transporter it use Web API, not Smtp)
// It is a safe dynamic import to avoid hard crash if package is missing

const SEND_REAL_MAIL = process.env.SEND_REAL_MAIL === "true";  //enable real mail delivery
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || "";  /// API key for SendGrid
let sgMail = null;   /// client reference 
let canDeliverToUser = false;  ///  whether if it enable the real delivery 

if (SEND_REAL_MAIL && SENDGRID_API_KEY) {    //// checking email if enabled and key present
  try {
    const mod = await import("@sendgrid/mail");    ///// Dynamic import
    sgMail = mod.default;  // Get default export ///
    sgMail.setApiKey(SENDGRID_API_KEY);   ///the Api key configure 
    canDeliverToUser = true;   /// user delivery - enable 
    console.log("SendGrid Web API: OK (API key loaded)");   /// log if success 
  } catch (e) {    
    console.warn("SendGrid init failed ->", e.message);/// log if failure 
    canDeliverToUser = false;  ////// disable delivery on failure
  }
} else {
  console.log("SendGrid disabled (SEND_REAL_MAIL not true or API key missing).");  /// inform user if it disable 
}

// Whether “activation email required” is enabled.
// Only require activation if we can actually deliver to the user.
const requireActivation = canDeliverToUser; ///// gate activation requirement on deliverability //
console.log("APP_BASE_URL:", APP_BASE_URL);  /// log app base URL  /// for debuging  
console.log("FRONTEND_ORIGINS:", FRONTEND_ORIGINS.join(", "));  //// log // Log allowed origins
console.log("DATA_DIR:", DATA_DIR);    /// data Dir log


// //////////////// Health -------------------------


app.get("/healthz", (_req, res) => res.json({ ok: true }));  /// check the healthz endpoint 

/////////// Activation Mail -----------------
/////   email view wihc user will see ni the activation email 
async function sendActivationEmail({ email, username, token }) {     /// compose and sen the activation emal 
  const activateUrl = `${APP_BASE_URL.replace(/\/$/, "")}/activate?token=${token}`;   //// link with activation  
  const html = `    
    <div style="font-family:system-ui,Segoe UI,Roboto,Arial;line-height:1.6">
      <h2>Activate your account</h2>
      <p>Hi ${validator.escape(username)}, thanks for registering.</p>    
      <p><a href="${activateUrl}" style="display:inline-block;padding:10px 16px;border-radius:8px;background:#4a6bff;color:#fff;text-decoration:none">
        Activate Account
      </a></p>
      <p>If the button doesn’t work: <a href="${activateUrl}">${activateUrl}</a></p> 
      <p>This link expires in ${TOKEN_TTL_HOURS} hours.</p>
    </div>`;

  // 2.1) Send real email to the user (SendGrid Web API)
  if (canDeliverToUser && sgMail) {
    await sgMail.send({    //// send via sendGrid if it's available
      from: EMAIL_FROM,
      to: email,
      subject: "Activate your Secure App account",
      html,
    });
  }

 /// // 2.2) Always send a copy to Mailtrap (if configured)
  if (trapTransport) {
    await trapTransport.sendMail({  // Send copy via Smtp
      from: EMAIL_FROM,
      to: "copy@example.com", // any address; Mailtrap captures it
      subject: `[COPY] Activation sent to ${email}`,
      html,
    });
  }
}

///////////////////////// Routes -------------------------

// POST /register { username, email, salt, verifier, vault }
app.post("/register", registerLimiter, async (req, res) => {     /// register new user 
  const { username, email, salt, verifier, vault } = req.body || {};    ///// extract the fields 
  if (!username || !email || !salt || !verifier || !vault) {    /////////
    return res.status(400).json({ error: "Missing fields" });          ///////  validate prisence
  }
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: "Invalid email" });   ///  validate email format 
  }

  const uname = lower(username);   //////// normalize username to lowercase
  const db = await loadDB();   /////  load DataBase

  if (db.users[uname]) {   
    return res.status(409).json({ error: "Username already exists" });   // Prevent duplicates
  }
  if (Object.values(db.users).some((u) => lower(u.email) === lower(email))) {
    return res.status(409).json({ error: "Email already registered" });   // Email uniqueness
  }

  const activationToken = genToken(32);    /// create the activation token 
  const activationExpiresAt = hoursFromNow(TOKEN_TTL_HOURS);    //// set expiry time  

  db.users[uname] = {       //// create user record in DataBase 
    username: uname,
    email,
    salt,
    verifier,
    isActivated: !requireActivation, // only require activation when we can deliver
    activationToken: requireActivation ? activationToken : undefined,     /////  store the token 
    activationExpiresAt: requireActivation ? activationExpiresAt : undefined,  ////   stoe the expiry 
  };
  db.vaults[uname] = vault;    ///// // Store user vault /////client-side encrypted//////

  await saveDB(db);   ///// perist Database

  if (!requireActivation) {
    // Dev/testing: no sendGrid ////// skip activation   ////////
    return res.json({
      ok: true,
      message: "Registered (email activation disabled). You can log in.",
      dev: true,
    }); // Early return when activation not required
  }

  try {
    await sendActivationEmail({ email, username: uname, token: activationToken });    ///// send to teh user activation email 
    return res.json({ ok: true, message: "Registration received. Check your email to activate." });    ///// success response 
  } catch (e) {
    // rollback if email was fails
    delete db.users[uname];    ////// remove user if is failed 
    delete db.vaults[uname];  ///// remove vault on failure 
    await saveDB(db);    //// rolback 
    return res.status(500).json({ error: "Failed to send activation email" });  ///// error status 5000 ////// error responce ///
  }
});

// GET ///// activate token  /////////////
app.get("/activate", async (req, res) => {    ///////// Activation Link handle //////////  
  const token = String(req.query?.token || "");   /////   query  ///// read token //////
  if (!token) return res.status(400).send("Invalid activation link");   //////  validate token 

  const db = await loadDB();    ////////   Load DataBase
  const entry = Object.values(db.users).find((u) => u.activationToken === token);  ///// find user by tokenn 

  if (!entry) return res.status(400).send("Invalid or already used activation token");    ////  validate token 
  if (new Date(entry.activationExpiresAt).getTime() < Date.now()) {    
    return res.status(400).send("Activation link has expired. Please re-register.");   //// checking if it expired
  }

  entry.isActivated = true;    ////  user activation mark 
  entry.activationToken = undefined;   /// clear token 
  entry.activationExpiresAt = undefined;  //// clear expire 
  await saveDB(db);       ///// perist Database

  res.redirect(`${FRONTEND_URL}/password-manager.html#activated`);  ///// redirect to the front end page  password-manager.html 
});

// POST and login //// username //////
app.post("/login", loginLimiter, async (req, res) => {   ///// login bootstarp 
  const uname = lower(req.body?.username);   ///// normalize username with lowercase 
  if (!uname) return res.status(400).json({ error: "Missing username" });   ///// validate input username 

  const db = await loadDB();   //// load DataBase 
  const user = db.users[uname];   //// lookup user   
  if (!user) return res.status(404).json({ error: "User not found" });   //// ensure at user exist 
  if (!user.isActivated) return res.status(403).json({ error: "Account not activated. Check your email." });   //// activation gate 

  res.json({   /////// return public Authentification params and vault  
    username: uname,   
    email: user.email,
    salt: user.salt,
    verifier: user.verifier,
    vault: db.vaults[uname],
  });
});

// POST /updateVault //// username and vault /////
app.post("/updateVault", async (req, res) => {   // Update stored /////encrypted ///// vault for user
  const uname = lower(req.body?.username);     ///// normalize username with lowercase 
  const vault = req.body?.vault;     // the new vault payload
  if (!uname || !vault) return res.status(400).json({ error: "Missing fields" });    /// input validation 

  const db = await loadDB();   //// load DataBase 
  const user = db.users[uname];   //// lookup user    
  if (!user || !user.isActivated) return res.status(403).json({ error: "Not allowed" });  //// must exist and be activated

  db.vaults[uname] = vault;  ///save new vault
  await saveDB(db);   /// persist data base 
  res.json({ ok: true });    ////// acknowledge 
});


// ----------------------- Admin APIs -----------------------

app.get("/admin/users", requireAdmin, async (_req, res) => {  //// List users  ///// admin only ///// 
  const db = await loadDB();      //// Load from Database 
  const list = Object.values(db.users).map((u) => ({  ////project save fields 
    username: u.username,   
    email: u.email,
    isActivated: !!u.isActivated,
  }));
  res.json({ users: list });  ////// respond with user list
});

//// to donwload db.json  ////////
app.get("/admin/db", (req, res) => {  
  if (req.headers["x-admin-key"] !== process.env.ADMIN_API_KEY)   
    return res.status(401).json({ error: "Unauthorized" });   //// error invalid autorization 

  res.sendFile(path.join(DATA_DIR, "db.json"));    
});

app.delete("/admin/users/:username", requireAdmin, async (req, res) => {   /////  delete user ///admin ////
  const uname = lower(req.params.username);  //// normalize path param 
  const db = await loadDB();   //// load from Database
  if (!db.users[uname]) return res.status(404).json({ error: "User not found" });  //// ensure, at is exist

  delete db.users[uname];   //// remove user record
  delete db.vaults[uname];  //// remove vault 
  await saveDB(db);   /// persist 

  res.json({ ok: true, message: `User ${uname} deleted` });   //// confirm deleteion 
});

app.post("/admin/resend-activation", requireAdmin, async (req, res) => {  ///// resend activation link /// admin /////

  const uname = lower(req.body?.username);  //// mnormalize username 
  if (!uname) return res.status(400).json({ error: "Missing username" });  ///// validate input 
 
  const db = await loadDB();   //// load from DataBase 
  const user = db.users[uname];     ///// lookup user ///
  if (!user) return res.status(404).json({ error: "User not found" });   //// user must exist 
  if (user.isActivated) return res.status(400).json({ error: "User already activated" });  ///// user must be pending
  if (!requireActivation) return res.status(400).json({ error: "Real mail disabled" });  ///// mail disabled

  user.activationToken = genToken(32);  /// new token 
  user.activationExpiresAt = hoursFromNow(TOKEN_TTL_HOURS);   /// new expiry 
  await saveDB(db);   /// saved dataBase

  try {
    await sendActivationEmail({ email: user.email, username: uname, token: user.activationToken }); // send mail 
    res.json({ ok: true, message: "Activation email resent" });  ///// success
  } catch (e) {
    res.status(500).json({ error: e.message || "Failed to send email" });  //// failure
  }
});


//////////////// Quick delivery test (sends to user and sends copy to Mailtrap) ---

app.get("/debug-mail", async (_req, res) => { // Test mail endpoints
  try {
    const to = process.env.TEST_TO || "apicomputerparts@gmail.com";      // Destination for test mail ////env override//////

    if (canDeliverToUser && sgMail) {   // Send via sendGrid if enabled
      await sgMail.send({
        from: EMAIL_FROM,
        to,
        subject: "SendGrid test (prod)",
        text: "Hello from SendGrid!",
      });
    }

    if (trapTransport) {    // Always send copy to Mailtrap if configured
      await trapTransport.sendMail({
        from: EMAIL_FROM,
        to: "copy@example.com",
        subject: "Mailtrap copy",
        text: "Hello from Mailtrap copy!",
      });
    }

    res.send("Sent test emails");  // respond succes
  } catch (e) {
    res.status(500).send(e.message);  // On error, respond 500 with mesage
  }
});



// ---------- Secure blob storage (encrypted client-side) ----------
// 50 MB limit
const MAX_BLOB_BYTES = 50 * 1024 * 1024;   //// maximum upload size in bytes
const FILES_DIR = path.join(DATA_DIR, "files");  /// directory to store blobs 
await fs.ensureDir(FILES_DIR);   //// files directory exist

const blobPath = (id) => path.join(FILES_DIR, `${id}.bin`);   ///// compute binary file path by id
const metaPath = (id) => path.join(FILES_DIR, `${id}.json`); /// // compute metadata Json path by id


// Post //files ////Json ///blobBase64, name, type ///// OR raw application/octet-stream//////
app.post("/files", async (req, res) => {   //// upload endpoint for blobs   d
  try {
    const ct = String(req.headers["content-type"] || "").toLowerCase();  //// normalize content type 

    let bin;    //// buffer for binary 
    let meta = { name: "", type: "" };  /// colect metadata 

    if (ct.startsWith("application/json")) {    //// handale base64 and Json payload  
      const body = req.body || {};    // Parsed Json body////
      if (!body.blobBase64) return res.status(400).json({ error: "Missing blobBase64" }); ///// validation
      meta.name = String(body.name || "");   //// optional name  
      meta.type = String(body.type || "");  // optional mime type
      bin = Buffer.from(body.blobBase64, "base64"); ///// decode base64 to buffer 
    } else if (ct.startsWith("application/octet-stream")) {   ////  handle raw binary 
      const chunks = [];
      let size = 0;   //// track total size
      await new Promise((resolve, reject) => {
        req.on("data", (c) => {   
          size += c.length;  //// update size 
          if (size > MAX_BLOB_BYTES) {   /// enforce max size 
            reject(new Error("File too large"));  //// reject if over limit 
            try { req.destroy(); } catch {}  /// best effort abort 
            return; //// stop processing 
          }
          chunks.push(c);  // /store the chunk
        });
        req.on("end", resolve);   /// resolve if is done 
        req.on("error", reject);  //// reject if error 
      });
      bin = Buffer.concat(chunks);  /// combine chunks in to single bufer 
    } else {
      return res.status(415).json({ error: "Unsupported Content-Type" });  //// reject Unsupported Content-Type
    }

    if (!bin?.length) return res.status(400).json({ error: "Empty payload" });  /////  // Must have content
    if (bin.length > MAX_BLOB_BYTES) return res.status(413).json({ error: "File too large" });  // Double-check size

    const id = crypto.randomUUID().replace(/-/g, "");   ///// Generate compact unique id 
    await fs.writeFile(blobPath(id), bin);     ////// Persist binary data
    await fs.writeJson(metaPath(id), { ...meta, size: bin.length, createdAt: new Date().toISOString() }, { spaces: 2 });
    res.json({ ok: true, id }); ////// Respond with id
  } catch (e) {
    res.status(400).json({ error: e.message || "Upload failed" }); // On error, respond 400
  }
});

// GET /////files/:id /////  returns the stored blob  ///////

app.get("/files/:id", async (req, res) => {  ////  // Download endpoint for blobs
  try {
    const id = String(req.params.id || "").toLowerCase().replace(/[^a-z0-9]/g, "");   ////// Sanitize id
    if (!id) return res.status(400).send("Bad id");   //// validation id 
    const p = blobPath(id);   // Compute file path
    if (!(await fs.pathExists(p))) return res.status(404).send("Not found");    /// ensure at file exixst 
    res.setHeader("Content-Type", "application/octet-stream");   //// set content type 
    res.setHeader("Cache-Control", "no-store");  /// disable caching 
    fs.createReadStream(p).pipe(res);   //// stream file to response
  } catch {
    res.status(500).send("Error");  //// if error 
  }
});

//////////////////simple debug helpers --------------------

console.log("Booting commit:", process.env.RENDER_GIT_COMMIT || "unknown");   ////// Log commit id if provided by host 
console.log("Files API enabled. Storing blobs in:", FILES_DIR);  ///// files dir 

app.get("/files-ping", (_req, res) => res.send("files routes loaded"));  /////// quick sanity ping for files router
app.get("/debug-routes", (_req, res) => {   //// register route for debugging
  const routes = [];      ////// // collect route info
  app._router.stack.forEach((m) => {     //// internal stack 
    if (m.route && m.route.path) {    /////// if layer has a route 
      const methods = Object.keys(m.route.methods).map((x) => x.toUpperCase());  //// collect methods
      routes.push({ methods, path: m.route.path });   /////// store path and methods
    }
  });
  res.json(routes);  ///// return to the routes list 
});

// ///////////////////Start ---------------------------
app.listen(PORT, () => {    ////// // Start HTTP server //////////////
  console.log(`Server listening on :${PORT}`);  ///////// / log listening port
});


