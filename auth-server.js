// BlackMamer Auth Server - Roblox OAuth2 + device-code buat plugin Studio
// (c) BlackMamerStudio
// ENV: RBX_CLIENT_ID, RBX_CLIENT_SECRET, BASE_URL (mis. https://xxx.onrender.com), PORT
// Redirect URI di Creator Hub: BASE_URL + /auth/callback   Scope: openid profile
// Butuh Node 18+ (fetch bawaan). npm i express

const express = require("express");
const crypto = require("crypto");

const { RBX_CLIENT_ID, RBX_CLIENT_SECRET, BASE_URL } = process.env;
const app = express();
app.use(express.json());

const pending = new Map(); // code -> { status, studioUserId, exp, token, userId, username }
const sessions = new Map(); // token -> { userId, username }
const rand = (n) => crypto.randomBytes(n).toString("hex");

setInterval(() => {
  for (const [k, v] of pending) if (v.exp < Date.now()) pending.delete(k);
}, 60e3);

app.post("/plugin/start", (req, res) => {
  const code = rand(4).toUpperCase();
  pending.set(code, {
    status: "pending",
    studioUserId: Number(req.body.studioUserId) || 0,
    exp: Date.now() + 5 * 60e3,
  });
  res.json({ code, url: `${BASE_URL}/auth/login?code=${code}`, expiresIn: 300 });
});

app.get("/auth/login", (req, res) => {
  if (!pending.has(req.query.code)) return res.status(400).send("Kode tidak valid / kadaluarsa");
  const url = new URL("https://apis.roblox.com/oauth/v1/authorize");
  url.search = new URLSearchParams({
    client_id: RBX_CLIENT_ID,
    redirect_uri: `${BASE_URL}/auth/callback`,
    scope: "openid profile",
    response_type: "code",
    state: req.query.code,
  });
  res.redirect(url.toString());
});

app.get("/auth/callback", async (req, res) => {
  const p = pending.get(req.query.state);
  if (!p) return res.status(400).send("State tidak valid / kadaluarsa");
  try {
    const tok = await fetch("https://apis.roblox.com/oauth/v1/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: RBX_CLIENT_ID,
        client_secret: RBX_CLIENT_SECRET,
        grant_type: "authorization_code",
        code: req.query.code,
        redirect_uri: `${BASE_URL}/auth/callback`,
      }),
    }).then((r) => r.json());
    if (!tok.access_token) throw new Error("no token");
    const me = await fetch("https://apis.roblox.com/oauth/v1/userinfo", {
      headers: { Authorization: `Bearer ${tok.access_token}` },
    }).then((r) => r.json());
    const userId = Number(me.sub);
    const username = me.preferred_username || me.name || String(userId);
    const token = rand(32);
    sessions.set(token, { userId, username });
    Object.assign(p, { status: "ok", token, userId, username });
    res.send("Berhasil login. Balik ke Roblox Studio.");
  } catch (e) {
    p.status = "denied";
    res.status(500).send("Login gagal");
  }
});

app.get("/plugin/poll", (req, res) => {
  const p = pending.get(req.query.code);
  if (!p) return res.json({ status: "denied" });
  if (p.status === "ok") {
    pending.delete(req.query.code);
    return res.json({ status: "ok", token: p.token, userId: p.userId, username: p.username });
  }
  res.json({ status: p.status });
});

app.get("/plugin/me", (req, res) => {
  const t = (req.headers.authorization || "").replace("Bearer ", "");
  const s = sessions.get(t);
  if (!s) return res.status(401).json({ error: "Sesi tidak valid" });
  res.json(s);
});

app.listen(process.env.PORT || 3000);
