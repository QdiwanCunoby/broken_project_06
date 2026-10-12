import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import jwt from "jsonwebtoken";
import { createApp } from "../src/app";
import { InMemoryUserRepository } from "../src/modules/auth/auth.repository";

const PASSWORD = "Password123!";
const NEW_PASSWORD = "NuovaPassword456?";

let repo: InMemoryUserRepository;
let app: ReturnType<typeof createApp>;

// Ogni test ha app (e quindi rate limiter) e repository nuovi
beforeEach(() => {
  repo = new InMemoryUserRepository();
  app = createApp(repo);
});

const cookiesOf = (res: request.Response): string[] => (res.headers["set-cookie"] as unknown as string[]) ?? [];
const register = (email = "test@liparibank.it", password = PASSWORD) =>
  request(app).post("/api/auth/register").send({ email, password });

// Registra + login: ritorna i cookie da rimandare nelle richieste successive
const loginAs = async (email = "test@liparibank.it", password = PASSWORD) => {
  await register(email, password);
  const res = await request(app).post("/api/auth/login").send({ email, password });
  expect(res.status).toBe(200);
  return cookiesOf(res);
};

describe("Bug 3 — register + login", () => {
  it("il login con le stesse credenziali della registrazione riesce (bcrypt.compare(plain, hash))", async () => {
    const reg = await register();
    expect(reg.status).toBe(201);
    expect(reg.body.data).not.toHaveProperty("passwordHash");

    const res = await request(app).post("/api/auth/login").send({ email: "test@liparibank.it", password: PASSWORD });
    expect(res.status).toBe(200);
    expect(res.body.data.email).toBe("test@liparibank.it");
  });

  it("password sbagliata → 401, email sconosciuta → 401 con lo stesso messaggio", async () => {
    await register();
    const wrong = await request(app).post("/api/auth/login").send({ email: "test@liparibank.it", password: "Sbagliata1!" });
    const unknown = await request(app).post("/api/auth/login").send({ email: "nessuno@liparibank.it", password: PASSWORD });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body.error.message).toBe(unknown.body.error.message);
  });

  it("l'hash salvato è bcrypt con cost 12", async () => {
    await register();
    const user = await repo.findByEmail("test@liparibank.it");
    expect(user!.passwordHash).toMatch(/^\$2[aby]\$12\$/);
  });

  it("email duplicata → 409, password debole → 422", async () => {
    await register();
    expect((await register()).status).toBe(409);
    expect((await register("altro@liparibank.it", "debole")).status).toBe(422);
  });
});

describe("Bug 2 — flag dei cookie", () => {
  it("access_token e refresh_token sono httpOnly + SameSite=Lax; il refresh ha path /api/auth/refresh", async () => {
    const cookies = await loginAs();
    const access = cookies.find(c => c.startsWith("access_token="))!;
    const refresh = cookies.find(c => c.startsWith("refresh_token="))!;

    for (const c of [access, refresh]) {
      expect(c).toContain("HttpOnly");
      expect(c).toContain("SameSite=Lax");
      expect(c).toMatch(/Max-Age=\d+/);
      expect(c).not.toContain("Secure");   // Secure solo con NODE_ENV=production (qui: test)
    }
    expect(access).toContain("Path=/;");
    expect(refresh).toContain("Path=/api/auth/refresh");
  });

  it("il token non compare nel body della risposta", async () => {
    await register();
    const res = await request(app).post("/api/auth/login").send({ email: "test@liparibank.it", password: PASSWORD });
    expect(JSON.stringify(res.body)).not.toMatch(/eyJ/);
  });
});

describe("authenticate prima delle route", () => {
  it("le route protette senza cookie rispondono 401", async () => {
    for (const path of ["/api/accounts", "/api/customers", "/api/transfers"]) {
      expect((await request(app).get(path)).status).toBe(401);
    }
  });

  it("un JWT firmato con un secret diverso (es. il vecchio 'secret123') è rifiutato", async () => {
    const user = await (async () => { await register(); return repo.findByEmail("test@liparibank.it"); })();
    const forged = jwt.sign({ sub: user!.id, role: "ADMIN", tv: 0 }, "secret123");
    const res = await request(app).get("/api/customers").set("Cookie", `access_token=${forged}`);
    expect(res.status).toBe(401);
  });
});

describe("POST /api/auth/refresh", () => {
  it("con il cookie refresh emette nuovi cookie; senza → 401", async () => {
    const cookies = await loginAs();
    const ok = await request(app).post("/api/auth/refresh").set("Cookie", cookies);
    expect(ok.status).toBe(204);
    expect(cookiesOf(ok).some(c => c.startsWith("access_token="))).toBe(true);

    expect((await request(app).post("/api/auth/refresh")).status).toBe(401);
  });

  it("un access token non è accettato come refresh (secret diversi)", async () => {
    const cookies = await loginAs();
    const access = cookies.find(c => c.startsWith("access_token="))!.split(";")[0].split("=")[1];
    const res = await request(app).post("/api/auth/refresh").set("Cookie", `refresh_token=${access}`);
    expect(res.status).toBe(401);
  });
});

describe("Feature — POST /api/auth/change-password", () => {
  const change = (cookies: string[], body: object) =>
    request(app).post("/api/auth/change-password").set("Cookie", cookies).send(body);

  it("senza sessione → 401", async () => {
    const res = await request(app).post("/api/auth/change-password").send({ currentPassword: PASSWORD, newPassword: NEW_PASSWORD });
    expect(res.status).toBe(401);
  });

  it("password attuale errata → 401", async () => {
    const cookies = await loginAs();
    const res = await change(cookies, { currentPassword: "Sbagliata1!", newPassword: NEW_PASSWORD });
    expect(res.status).toBe(401);
  });

  it("nuova password uguale all'attuale o debole → 422", async () => {
    const cookies = await loginAs();
    expect((await change(cookies, { currentPassword: PASSWORD, newPassword: PASSWORD })).status).toBe(422);
    expect((await change(cookies, { currentPassword: PASSWORD, newPassword: "debole" })).status).toBe(422);
  });

  it("cambio riuscito: 204, cookie puliti, nuova password funziona, la vecchia no", async () => {
    const cookies = await loginAs();
    const res = await change(cookies, { currentPassword: PASSWORD, newPassword: NEW_PASSWORD });
    expect(res.status).toBe(204);

    const cleared = cookiesOf(res);
    expect(cleared.find(c => c.startsWith("access_token="))).toContain("Expires=Thu, 01 Jan 1970");
    expect(cleared.find(c => c.startsWith("refresh_token="))).toMatch(/Path=\/api\/auth\/refresh.*Expires=Thu, 01 Jan 1970/);

    const email = "test@liparibank.it";
    expect((await request(app).post("/api/auth/login").send({ email, password: PASSWORD })).status).toBe(401);
    expect((await request(app).post("/api/auth/login").send({ email, password: NEW_PASSWORD })).status).toBe(200);
  });

  it("i token emessi PRIMA del cambio password (furto di sessione) smettono subito di funzionare", async () => {
    const stolen = await loginAs();   // sessione dell'utente, copiata dall'attaccante
    // Prima del cambio la sessione "rubata" è valida
    expect((await request(app).post("/api/auth/refresh").set("Cookie", stolen)).status).toBe(204);

    expect((await change(stolen, { currentPassword: PASSWORD, newPassword: NEW_PASSWORD })).status).toBe(204);

    // L'attaccante ha ancora i cookie vecchi: access E refresh devono essere rifiutati
    expect((await request(app).get("/api/customers").set("Cookie", stolen)).status).toBe(401);
    expect((await request(app).post("/api/auth/refresh").set("Cookie", stolen)).status).toBe(401);
    expect((await change(stolen, { currentPassword: NEW_PASSWORD, newPassword: "AltraPassword789#" })).status).toBe(401);
  });

  it("rate limit: dal 4° tentativo in 15 minuti → 429", async () => {
    const cookies = await loginAs();
    const attempt = () => change(cookies, { currentPassword: "Sbagliata1!", newPassword: NEW_PASSWORD });
    expect((await attempt()).status).toBe(401);
    expect((await attempt()).status).toBe(401);
    expect((await attempt()).status).toBe(401);
    const blocked = await attempt();
    expect(blocked.status).toBe(429);
    expect(blocked.body.error.code).toBe("TOO_MANY_REQUESTS");
  });
});

describe("Bug 1 — fail fast sui secret", () => {
  const loadEnv = async (vars: Record<string, string | undefined>) => {
    const saved = { ...process.env };
    Object.assign(process.env, vars);
    for (const k of Object.keys(vars)) if (vars[k] === undefined) delete process.env[k];
    try {
      const { vi } = await import("vitest");
      vi.resetModules();
      return await import("../src/config/env");
    } finally {
      process.env = saved;
    }
  };

  it("senza JWT_SECRET l'import di env lancia", async () => {
    await expect(loadEnv({ JWT_SECRET: undefined })).rejects.toThrow(/JWT_SECRET/);
  });

  it("senza JWT_REFRESH_SECRET lancia", async () => {
    await expect(loadEnv({ JWT_REFRESH_SECRET: undefined })).rejects.toThrow(/JWT_REFRESH_SECRET/);
  });

  it("secret troppo corto o uguali tra loro → lancia", async () => {
    await expect(loadEnv({ JWT_SECRET: "corto" })).rejects.toThrow(/troppo corto/);
    const same = "x".repeat(40);
    await expect(loadEnv({ JWT_SECRET: same, JWT_REFRESH_SECRET: same })).rejects.toThrow(/diversi/);
  });
});
