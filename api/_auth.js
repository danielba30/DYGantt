const crypto = require("crypto");

/** בודק את סיסמת העריכה מול משתנה הסביבה EDIT_PASSWORD (בצד השרת בלבד) */
function checkPassword(pw) {
  const expected = process.env.EDIT_PASSWORD;
  if (!expected) return "unconfigured";
  if (typeof pw !== "string" || !pw) return false;
  const a = crypto.createHash("sha256").update(pw).digest();
  const b = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

const wait = ms => new Promise(r => setTimeout(r, ms));

module.exports = { checkPassword, wait };
