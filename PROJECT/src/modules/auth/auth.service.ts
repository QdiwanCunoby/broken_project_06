// Service: logica di autenticazione. Non conosce HTTP né cookie.
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { env } from "../../config/env";
import { ConflictError, UnauthorizedError } from "../../utils/errors";
import { UserRepository } from "./auth.repository";
import {
  AccessTokenPayload, AuthUser, ChangePasswordInput, LoginInput, PublicUser,
  RefreshTokenPayload, RegisterInput, User, UUID,
} from "./auth.types";

export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;
export const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;
const BCRYPT_ROUNDS = 12;
const INVALID_CREDENTIALS = "Credenziali non valide";

const toPublic = (u: User): PublicUser => ({ id: u.id, email: u.email, role: u.role, createdAt: u.createdAt });

export class AuthService {
  constructor(private readonly users: UserRepository) {}

  signAccessToken(user: Pick<User, "id" | "role" | "tokenVersion">): string {
    const payload: AccessTokenPayload = { sub: user.id, role: user.role, tv: user.tokenVersion };
    return jwt.sign(payload, env.jwtSecret, { algorithm: "HS256", expiresIn: ACCESS_TOKEN_TTL_SECONDS });
  }

  signRefreshToken(user: Pick<User, "id" | "tokenVersion">): string {
    const payload: RefreshTokenPayload = { sub: user.id, tv: user.tokenVersion };
    return jwt.sign(payload, env.jwtRefreshSecret, { algorithm: "HS256", expiresIn: REFRESH_TOKEN_TTL_SECONDS });
  }

  // Verifica la firma e carica l'utente: il token è valido solo se la tokenVersion coincide
  // con quella nel DB (cambio password → tokenVersion++ → tutti i token precedenti rifiutati).
  async verifyAccessToken(token: string): Promise<AuthUser> {
    const payload = this.verify<AccessTokenPayload>(token, env.jwtSecret);
    const user = await this.loadValidUser(payload.sub, payload.tv);
    return { id: user.id, role: user.role };
  }

  async register(input: RegisterInput): Promise<PublicUser> {
    if (await this.users.findByEmail(input.email)) throw new ConflictError("Email già registrata", "EMAIL_TAKEN");
    const passwordHash = await bcrypt.hash(input.password, BCRYPT_ROUNDS);
    return toPublic(await this.users.create({ email: input.email, passwordHash }));
  }

  async login(input: LoginInput) {
    const user = await this.users.findByEmail(input.email);
    if (!user) throw new UnauthorizedError(INVALID_CREDENTIALS);

    // bcrypt.compare(plain, hash): l'ordine conta ed entrambi sono `string`, quindi TypeScript non lo controlla
    const ok = await bcrypt.compare(input.password, user.passwordHash);
    if (!ok) throw new UnauthorizedError(INVALID_CREDENTIALS);

    return { user: toPublic(user), accessToken: this.signAccessToken(user), refreshToken: this.signRefreshToken(user) };
  }

  async refresh(refreshToken: string) {
    const payload = this.verify<RefreshTokenPayload>(refreshToken, env.jwtRefreshSecret);
    const user = await this.loadValidUser(payload.sub, payload.tv);
    return { accessToken: this.signAccessToken(user), refreshToken: this.signRefreshToken(user) };
  }

  async changePassword(userId: UUID, input: ChangePasswordInput): Promise<void> {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedError();

    // 401 e non 400: stesso pattern del login (fallimento di autenticazione)
    const ok = await bcrypt.compare(input.currentPassword, user.passwordHash);
    if (!ok) throw new UnauthorizedError("Password attuale non corretta");

    // updatePassword incrementa anche tokenVersion → sessioni esistenti invalidate
    await this.users.updatePassword(user.id, await bcrypt.hash(input.newPassword, BCRYPT_ROUNDS));
  }

  private verify<T extends { sub: UUID; tv: number }>(token: string, secret: string): T {
    try {
      const payload = jwt.verify(token, secret, { algorithms: ["HS256"] });
      if (typeof payload === "string" || typeof payload.sub !== "string" || typeof payload.tv !== "number") {
        throw new Error("payload non valido");
      }
      return payload as unknown as T;
    } catch {
      throw new UnauthorizedError("Token non valido o scaduto");
    }
  }

  private async loadValidUser(id: UUID, tokenVersion: number): Promise<User> {
    const user = await this.users.findById(id);
    if (!user || user.tokenVersion !== tokenVersion) throw new UnauthorizedError("Sessione non più valida");
    return user;
  }
}
