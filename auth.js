const crypto = require("crypto");
const argon2 = require("argon2");

function b64(buf) {
  return Buffer.from(buf).toString("base64").replace(/=+$/, "");
}

const PEPPER_B64 = process.env.AEGIS_PEPPER_B64 || "";
if (!PEPPER_B64) {
  console.error("ERROR: AEGIS_PEPPER_B64 environment variable not set. Exiting.");
  process.exit(1);
}
const PEPPER = Buffer.from(PEPPER_B64, "base64");

const DEFAULT_M = 65536;
const DEFAULT_T = 3;
const DEFAULT_P = 1;
const DEFAULT_OUTLEN = 32;

async function hashPassword(userInput) {
  if (typeof userInput !== "string" && !Buffer.isBuffer(userInput)) {
    throw new Error("password must be string or Buffer");
  }

  let password = typeof userInput === "string" ? userInput.normalize("NFC") : userInput;
  if (typeof password === "string" && password.length > 1024) {
    password = crypto.createHash("sha512").update(password, "utf8").digest();
  } else if (typeof password === "string") {
    password = Buffer.from(password, "utf8");
  }

  const salt = crypto.randomBytes(16);

  const hashBytes = await argon2.hash(password, {
    type: argon2.argon2id,
    timeCost: DEFAULT_T,
    memoryCost: DEFAULT_M,
    parallelism: DEFAULT_P,
    salt,
    hashLength: DEFAULT_OUTLEN,
    raw: true
  });

  const hmacTag = crypto.createHmac("sha256", PEPPER)
                        .update(Buffer.concat([hashBytes, salt]))
                        .digest();

  const encoded = `$AegisHash$v1$argon2id$m=${DEFAULT_M},t=${DEFAULT_T},p=${DEFAULT_P}$${b64(salt)}$${b64(hashBytes)}$${b64(hmacTag)}`;
  return encoded;
}

async function verifyPassword(userInput, encoded) {
  try {
    if (!encoded || typeof encoded !== "string") return false;
    const parts = encoded.split("$");
    if (parts.length < 9) return false;
    if (parts[1] !== "AegisHash" || parts[2] !== "v1") return false;

    const params = parts[5];
    const [mPart, tPart, pPart] = params.split(",");
    const m = parseInt(mPart.split("=")[1], 10);
    const t = parseInt(tPart.split("=")[1], 10);
    const p = parseInt(pPart.split("=")[1], 10);

    const salt = Buffer.from(parts[6], "base64");
    const hashBytes = Buffer.from(parts[7], "base64");
    const expectedHmac = Buffer.from(parts[8], "base64");

    let password = typeof userInput === "string" ? userInput.normalize("NFC") : userInput;
    if (typeof password === "string" && password.length > 1024) {
      password = crypto.createHash("sha512").update(password, "utf8").digest();
    } else if (typeof password === "string") {
      password = Buffer.from(password, "utf8");
    }

    const derivedHash = await argon2.hash(password, {
      type: argon2.argon2id,
      timeCost: t,
      memoryCost: m,
      parallelism: p,
      salt,
      hashLength: hashBytes.length,
      raw: true
    });

    const derivedHmac = crypto.createHmac("sha256", PEPPER)
                              .update(Buffer.concat([derivedHash, salt]))
                              .digest();

    const okHash = derivedHash.length === hashBytes.length && crypto.timingSafeEqual(derivedHash, hashBytes);
    const okHmac = derivedHmac.length === expectedHmac.length && crypto.timingSafeEqual(derivedHmac, expectedHmac);

    return okHash && okHmac;
  } catch (e) {
    console.error("verifyPassword error:", e && e.message ? e.message : e);
    return false;
  }
}

module.exports = { hashPassword, verifyPassword };
