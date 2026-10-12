const crypto = require("crypto");
const { checkPassword, wait } = require("./_auth");

const ID_RE = /^[a-z0-9]{6,20}$/;
const MAX_BYTES = 400 * 1024;
const pathOf = id => `shares/${id}.json`;

function newId() {
  // 8 תווים אקראיים (a-z0-9) — קשה לניחוש
  const bytes = crypto.randomBytes(8);
  let s = "";
  for (const b of bytes) s += "abcdefghijklmnopqrstuvwxyz0123456789"[b % 36];
  return s;
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const blob = await import("@vercel/blob");

  /* ---- קריאה: פתוחה לכל מי שיש לו את המזהה ---- */
  if (req.method === "GET") {
    const id = String((req.query || {}).id || "");
    if (!ID_RE.test(id)) return res.status(400).json({ error: "bad_id" });
    try {
      const r = await blob.get(pathOf(id), { access: "private", useCache: false });
      if (!r || r.statusCode !== 200 || !r.stream) return res.status(404).json({ error: "not_found" });
      const text = await new Response(r.stream).text();
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      return res.status(200).send(text);
    } catch (e) {
      return res.status(404).json({ error: "not_found" });
    }
  }

  /* ---- כתיבה ומחיקה: דורשות את סיסמת העריכה ---- */
  if (req.method === "POST" || req.method === "DELETE") {
    const body = req.body || {};
    const ok = checkPassword(body.password);
    if (ok === "unconfigured") return res.status(503).json({ error: "unconfigured" });
    if (!ok) { await wait(500); return res.status(401).json({ error: "bad_password" }); }

    if (req.method === "DELETE") {
      const id = String(body.id || "");
      if (!ID_RE.test(id)) return res.status(400).json({ error: "bad_id" });
      try { await blob.del(pathOf(id)); } catch (e) { /* כבר לא קיים */ }
      return res.status(200).json({ ok: true });
    }

    const data = body.data;
    if (!data || !Array.isArray(data.tasks)) return res.status(400).json({ error: "bad_data" });
    let id = body.id ? String(body.id) : newId();
    if (!ID_RE.test(id)) return res.status(400).json({ error: "bad_id" });

    const payload = JSON.stringify({ v: 1, app: "mini-gantt", at: new Date().toISOString(), data });
    if (Buffer.byteLength(payload) > MAX_BYTES) return res.status(413).json({ error: "too_large" });

    await blob.put(pathOf(id), payload, {
      access: "private",
      contentType: "application/json",
      addRandomSuffix: false,
      allowOverwrite: true
    });
    return res.status(200).json({ id });
  }

  res.setHeader("Allow", "GET, POST, DELETE");
  return res.status(405).json({ error: "method_not_allowed" });
};
