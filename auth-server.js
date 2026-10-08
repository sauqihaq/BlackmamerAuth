// BlackMamer Auth Server - Roblox OAuth2 + Open Cloud Assets API
// Node 18+
// ENV: RBX_CLIENT_ID, RBX_CLIENT_SECRET, BASE_URL, PORT(optional)
// Redirect URI: BASE_URL + /auth/callback
// OAuth scopes: openid profile asset:read asset:write

const express = require("express");
const crypto = require("crypto");

const { RBX_CLIENT_ID, RBX_CLIENT_SECRET, BASE_URL } = process.env;
const app = express();
app.use(express.json({ limit: "40mb" }));

const pending = new Map();
// token -> { userId, username, accessToken, refreshToken, expiresAt }
const sessions = new Map();

const rand = (n) => crypto.randomBytes(n).toString("hex");

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pending) if (v.exp < now) pending.delete(k);
  for (const [k, v] of sessions) {
    if (v.sessionExp && v.sessionExp < now) sessions.delete(k);
  }
}, 60e3);

function requireEnv() {
  if (!RBX_CLIENT_ID || !RBX_CLIENT_SECRET || !BASE_URL) {
    throw new Error("RBX_CLIENT_ID, RBX_CLIENT_SECRET, dan BASE_URL wajib diisi");
  }
}

async function robloxTokenRequest(body) {
  const r = await fetch("https://apis.roblox.com/oauth/v1/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok || !data.access_token) {
    throw new Error(data.error_description || data.error || `OAuth token HTTP ${r.status}`);
  }
  return data;
}

async function fetchUser(accessToken) {
  const r = await fetch("https://apis.roblox.com/oauth/v1/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok || !data.sub) throw new Error(data.error || `userinfo HTTP ${r.status}`);
  return data;
}

async function ensureAccessToken(session) {
  // Refresh a little before expiry.
  if (session.accessToken && session.expiresAt && Date.now() < session.expiresAt - 60_000) {
    return session.accessToken;
  }

  if (!session.refreshToken) {
    throw new Error("OAuth session habis. Login Roblox lagi.");
  }

  const tok = await robloxTokenRequest({
    client_id: RBX_CLIENT_ID,
    client_secret: RBX_CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: session.refreshToken,
  });

  session.accessToken = tok.access_token;
  session.refreshToken = tok.refresh_token || session.refreshToken;
  session.expiresAt = Date.now() + Number(tok.expires_in || 3600) * 1000;
  return session.accessToken;
}

function getSession(req) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  return sessions.get(token) || null;
}

app.get("/", (req, res) => {
  res.json({ ok: true, service: "BlackMamer Auth", version: 2 });
});

app.post("/plugin/start", (req, res) => {
  try {
    requireEnv();
    const code = rand(4).toUpperCase();
    pending.set(code, {
      status: "pending",
      studioUserId: Number(req.body?.studioUserId) || 0,
      exp: Date.now() + 5 * 60e3,
    });
    res.json({ code, url: `${BASE_URL}/auth/login?code=${encodeURIComponent(code)}`, expiresIn: 300 });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/auth/login", (req, res) => {
  requireEnv();
  if (!pending.has(req.query.code)) return res.status(400).send("Kode tidak valid / kadaluarsa");

  const url = new URL("https://apis.roblox.com/oauth/v1/authorize");
  url.search = new URLSearchParams({
    client_id: RBX_CLIENT_ID,
    redirect_uri: `${BASE_URL}/auth/callback`,
    scope: "openid profile asset:read asset:write",
    response_type: "code",
    state: req.query.code,
  });
  res.redirect(url.toString());
});

app.get("/auth/callback", async (req, res) => {
  requireEnv();
  const p = pending.get(req.query.state);
  if (!p) return res.status(400).send("State tidak valid / kadaluarsa");

  try {
    const tok = await robloxTokenRequest({
      client_id: RBX_CLIENT_ID,
      client_secret: RBX_CLIENT_SECRET,
      grant_type: "authorization_code",
      code: req.query.code,
      redirect_uri: `${BASE_URL}/auth/callback`,
    });

    const me = await fetchUser(tok.access_token);
    const userId = Number(me.sub);
    const username = me.preferred_username || me.name || String(userId);

    const sessionToken = rand(32);
    sessions.set(sessionToken, {
      userId,
      username,
      accessToken: tok.access_token,
      refreshToken: tok.refresh_token || null,
      expiresAt: Date.now() + Number(tok.expires_in || 3600) * 1000,
      sessionExp: Date.now() + 30 * 24 * 60 * 60 * 1000,
    });

    Object.assign(p, { status: "ok", token: sessionToken, userId, username });
    res.send("Berhasil login. Balik ke Roblox Studio.");
  } catch (e) {
    p.status = "denied";
    console.error("OAuth callback:", e);
    res.status(500).send("Login gagal: " + e.message);
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

app.get("/plugin/me", async (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "Sesi tidak valid" });
  res.json({ userId: s.userId, username: s.username });
});

function f32Buffer(values) {
  const b = Buffer.allocUnsafe(values.length * 4);
  for (let i = 0; i < values.length; i++) b.writeFloatLE(Number(values[i]) || 0, i * 4);
  return b;
}

function u16Buffer(values) {
  const b = Buffer.allocUnsafe(values.length * 2);
  for (let i = 0; i < values.length; i++) b.writeUInt16LE(Number(values[i]) || 0, i * 2);
  return b;
}

function u32Buffer(values) {
  const b = Buffer.allocUnsafe(values.length * 4);
  for (let i = 0; i < values.length; i++) b.writeUInt32LE(Number(values[i]) || 0, i * 4);
  return b;
}

function pad4(buf, byte = 0) {
  const n = (4 - (buf.length % 4)) % 4;
  return n ? Buffer.concat([buf, Buffer.alloc(n, byte)]) : buf;
}

function makeGlb(mesh) {
  const positions = mesh.positions || [];
  const normals = mesh.normals || [];
  const colors = mesh.colors || [];
  const indices = mesh.indices || [];

  if (!Array.isArray(positions) || positions.length < 9) throw new Error("Geometry kosong");
  if (!Array.isArray(indices) || indices.length < 3) throw new Error("Triangle kosong");
  if (positions.length % 3 !== 0) throw new Error("positions invalid");
  if (normals.length && normals.length !== positions.length) throw new Error("normals invalid");
  if (colors.length && colors.length !== (positions.length / 3) * 4) throw new Error("colors invalid");

  const vertexCount = positions.length / 3;
  if (vertexCount > 65535) {
    // Plugin currently sends a duplicated vertex per face. Keep the format simple and
    // use uint32 indices for large meshes.
  }

  const chunks = [];
  const bufferViews = [];
  const accessors = [];
  let offset = 0;

  function addView(buf, target) {
    const padded = pad4(buf, 0);
    const idx = bufferViews.length;
    bufferViews.push({ buffer: 0, byteOffset: offset, byteLength: buf.length, ...(target ? { target } : {}) });
    chunks.push(padded);
    offset += padded.length;
    return idx;
  }

  function addAccessor(view, componentType, count, type, min, max, normalized = false) {
    const idx = accessors.length;
    accessors.push({ bufferView: view, componentType, count, type, ...(min ? { min } : {}), ...(max ? { max } : {}), ...(normalized ? { normalized: true } : {}) });
    return idx;
  }

  const posBuf = f32Buffer(positions);
  const posMin = [Infinity, Infinity, Infinity];
  const posMax = [-Infinity, -Infinity, -Infinity];
  for (let i = 0; i < positions.length; i += 3) {
    for (let j = 0; j < 3; j++) {
      posMin[j] = Math.min(posMin[j], positions[i + j]);
      posMax[j] = Math.max(posMax[j], positions[i + j]);
    }
  }
  const posView = addView(posBuf, 34962);
  const posAcc = addAccessor(posView, 5126, vertexCount, "VEC3", posMin, posMax);

  let normAcc = null;
  if (normals.length) {
    normAcc = addAccessor(addView(f32Buffer(normals), 34962), 5126, vertexCount, "VEC3");
  }

  let colorAcc = null;
  if (colors.length) {
    colorAcc = addAccessor(addView(Buffer.from(colors.map(v => Math.max(0, Math.min(255, Math.round(Number(v) * 255))))), 34962), 5121, vertexCount, "VEC4", null, null, true);
  }

  const maxIndex = Math.max(...indices);
  let indexAcc;
  if (maxIndex <= 65535) {
    indexAcc = addAccessor(addView(u16Buffer(indices), 34963), 5123, indices.length, "SCALAR");
  } else {
    indexAcc = addAccessor(addView(u32Buffer(indices), 34963), 5125, indices.length, "SCALAR");
  }

  const primitive = {
    attributes: { POSITION: posAcc },
    indices: indexAcc,
    mode: 4,
  };
  if (normAcc !== null) primitive.attributes.NORMAL = normAcc;
  if (colorAcc !== null) primitive.attributes.COLOR_0 = colorAcc;

  const gltf = {
    asset: { version: "2.0", generator: "BlackMamer 3D Convert" },
    scene: 0,
    scenes: [{ nodes: [0] }],
    nodes: [{ mesh: 0, name: mesh.name || "BlackMamerMesh" }],
    meshes: [{ name: mesh.name || "BlackMamerMesh", primitives: [primitive] }],
    buffers: [{ byteLength: offset }],
    bufferViews,
    accessors,
  };

  const json = pad4(Buffer.from(JSON.stringify(gltf), "utf8"), 0x20);
  const bin = Buffer.concat(chunks);
  const total = 12 + 8 + json.length + 8 + bin.length;

  const header = Buffer.alloc(12);
  header.writeUInt32LE(0x46546c67, 0);
  header.writeUInt32LE(2, 4);
  header.writeUInt32LE(total, 8);

  const jh = Buffer.alloc(8);
  jh.writeUInt32LE(json.length, 0);
  jh.writeUInt32LE(0x4e4f534a, 4);

  const bh = Buffer.alloc(8);
  bh.writeUInt32LE(bin.length, 0);
  bh.writeUInt32LE(0x004e4942, 4);

  return Buffer.concat([header, jh, json, bh, bin]);
}

function cleanName(name) {
  return String(name || "BlackMamer SVG")
    .replace(/[\\/:*?"<>|]/g, "_")
    .slice(0, 100) || "BlackMamer SVG";
}

async function uploadModelWithOAuth(session, glb, displayName) {
  const accessToken = await ensureAccessToken(session);

  const form = new FormData();
  form.append("request", JSON.stringify({
    assetType: "Model",
    displayName,
    description: "Dibuat dengan BlackMamer 3D Convert",
    creationContext: { creator: { userId: String(session.userId) } },
  }));
  form.append("fileContent", new Blob([glb], { type: "model/gltf-binary" }), "model.glb");

  const r = await fetch("https://apis.roblox.com/assets/v1/assets", {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}` },
    body: form,
  });

  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401) {
      session.accessToken = null;
    }
    throw new Error(data.message || data.error || `Roblox Assets API HTTP ${r.status}`);
  }
  if (!data.path) throw new Error("Roblox tidak mengembalikan operation path");
  return data.path;
}

app.post("/plugin/upload", async (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "Sesi tidak valid. Login Roblox lagi." });

  try {
    const body = req.body || {};
    const mesh = body.mesh;
    if (!mesh) throw new Error("Payload mesh tidak ada");

    const positions = mesh.positions || [];
    const indices = mesh.indices || [];
    if (positions.length / 3 > 200000) throw new Error("Mesh terlalu besar");
    if (indices.length / 3 > 100000) throw new Error("Terlalu banyak triangle");

    const glb = makeGlb(mesh);
    if (glb.length > 20 * 1024 * 1024) throw new Error("GLB melebihi batas 20 MB Roblox");

    const operationPath = await uploadModelWithOAuth(session, glb, cleanName(body.name));
    const operationId = operationPath.split("/").pop();

    res.json({ ok: true, operationPath, operationId });
  } catch (e) {
    console.error("Upload:", e);
    res.status(400).json({ error: e.message || "Upload gagal" });
  }
});

app.get("/plugin/upload-status", async (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "Sesi tidak valid" });

  try {
    const accessToken = await ensureAccessToken(session);
    const id = String(req.query.operationId || "").replace(/^.*\//, "");
    if (!id) return res.status(400).json({ error: "operationId wajib" });

    const r = await fetch(`https://apis.roblox.com/assets/v1/operations/${encodeURIComponent(id)}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.message || data.error || `Operation HTTP ${r.status}`);

    if (!data.done) return res.json({ done: false });
    if (data.error) return res.json({ done: true, ok: false, error: data.error.message || JSON.stringify(data.error) });

    const assetId = Number(data.response?.assetId);
    if (!assetId) throw new Error("Operation selesai tetapi assetId tidak ditemukan");
    res.json({ done: true, ok: true, assetId });
  } catch (e) {
    res.status(400).json({ error: e.message || "Gagal cek upload" });
  }
});

requireEnv();
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`BlackMamer Auth listening on ${port}`));
