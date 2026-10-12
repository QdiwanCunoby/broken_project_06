// Route: connette URL → Controller. Le dipendenze arrivano dal composition root (app.ts).
import { RequestHandler, Router } from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";
import { AuthController } from "./auth.controller";
import { changePasswordSchema, loginSchema, registerSchema } from "./auth.types";
import { validate } from "../../middleware/validate";
import { fail } from "../../utils/apiResponse";

// Cambio password: 3 tentativi / 15 min per IP + userId (anti brute-force sulla password corrente).
// Va dopo authenticate perché la chiave usa req.user.
const changePasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 3,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: req => `${ipKeyGenerator(req.ip ?? "")}:${req.user?.id ?? "anonymous"}`,
  handler: (_req, res) => {
    res.status(429).json(fail("TOO_MANY_REQUESTS", "Troppi tentativi di cambio password, riprova tra 15 minuti"));
  },
});

export const createAuthRoutes = (controller: AuthController, authenticate: RequestHandler): Router => {
  const router = Router();

  router.post("/register", validate(registerSchema), controller.register);   // 201 | 422 | 409
  router.post("/login",    validate(loginSchema), controller.login);         // 200 + cookie | 422 | 401
  router.post("/refresh",  controller.refresh);                              // 204 + nuovi cookie | 401
  router.post("/logout",   controller.logout);                               // 204

  router.post("/change-password", authenticate, changePasswordLimiter, validate(changePasswordSchema), controller.changePassword); // 204 | 401 | 422 | 429

  return router;
};
