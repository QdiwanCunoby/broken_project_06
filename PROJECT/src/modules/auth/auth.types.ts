import { z } from "zod";

export type UUID = string;
export type Role = "USER" | "ADMIN";

export interface User {
  id: UUID;
  email: string;
  passwordHash: string;
  role: Role;
  tokenVersion: number;
  createdAt: Date;
  updatedAt: Date;
}

// Utente esposto al client: mai passwordHash né tokenVersion
export type PublicUser = Pick<User, "id" | "email" | "role" | "createdAt">;

// Claim dei JWT: `tv` = tokenVersion dell'utente al momento dell'emissione
export interface AccessTokenPayload { sub: UUID; role: Role; tv: number }
export interface RefreshTokenPayload { sub: UUID; tv: number }

// Utente autenticato, popolato da `authenticate` in req.user
export interface AuthUser { id: UUID; role: Role }

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request { user?: AuthUser }
  }
}

// ─── Schemi Zod ───
const emailSchema = z
  .string({ message: "Email obbligatoria" })
  .trim()
  .toLowerCase()
  .pipe(z.email({ message: "Email non valida" }));

// Password policy: 8-72 caratteri (bcrypt tronca oltre 72 byte), maiuscola, minuscola, cifra, simbolo
export const passwordPolicy = z
  .string({ message: "Password obbligatoria" })
  .min(8, { message: "Password: minimo 8 caratteri" })
  .max(72, { message: "Password: massimo 72 caratteri" })
  .regex(/[a-z]/, { message: "Password: serve almeno una minuscola" })
  .regex(/[A-Z]/, { message: "Password: serve almeno una maiuscola" })
  .regex(/\d/, { message: "Password: serve almeno una cifra" })
  .regex(/[^A-Za-z0-9]/, { message: "Password: serve almeno un simbolo" });

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordPolicy,
});

// Il login NON applica la policy: non deve rivelare le regole né rifiutare password legacy
export const loginSchema = z.object({
  email: emailSchema,
  password: z.string({ message: "Password obbligatoria" }).min(1, { message: "Password obbligatoria" }),
});

export const changePasswordSchema = z
  .object({
    currentPassword: z.string({ message: "Password attuale obbligatoria" }).min(1, { message: "Password attuale obbligatoria" }),
    newPassword: passwordPolicy,
  })
  .refine(d => d.currentPassword !== d.newPassword, {
    path: ["newPassword"],
    message: "La nuova password deve essere diversa da quella attuale",
  });

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
