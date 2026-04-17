import bcrypt from "bcrypt";
const hash = await bcrypt.hash("admin123", 10);
console.log(hash);