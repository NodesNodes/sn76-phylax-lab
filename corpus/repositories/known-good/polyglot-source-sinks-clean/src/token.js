import crypto from "node:crypto";
export function issue() {
  const token = crypto.randomBytes(32).toString("hex");
  return token;
}
