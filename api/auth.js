const { checkPassword, wait } = require("./_auth");

/** POST {password} -> 200 אם הסיסמה נכונה, 401 אם שגויה, 503 אם השרת לא הוגדר */
module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });
  const ok = checkPassword((req.body || {}).password);
  if (ok === "unconfigured") return res.status(503).json({ error: "unconfigured" });
  if (!ok) { await wait(500); return res.status(401).json({ error: "bad_password" }); }
  return res.status(200).json({ ok: true });
};
