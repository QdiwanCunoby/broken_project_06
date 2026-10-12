// Repository utenti: interfaccia + implementazione Prisma + implementazione in memoria (per i test)
import { randomUUID } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { Role, User, UUID } from "./auth.types";

export interface UserRepository {
  findByEmail(email: string): Promise<User | null>;
  findById(id: UUID): Promise<User | null>;
  create(data: { email: string; passwordHash: string; role?: Role }): Promise<User>;
  // Aggiorna l'hash E incrementa tokenVersion nella stessa operazione: invalida tutti i JWT già emessi
  updatePassword(id: UUID, passwordHash: string): Promise<void>;
}

export class PrismaUserRepository implements UserRepository {
  constructor(private readonly prisma: PrismaClient) {}

  findByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }

  findById(id: UUID) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  create(data: { email: string; passwordHash: string; role?: Role }) {
    return this.prisma.user.create({ data });
  }

  async updatePassword(id: UUID, passwordHash: string) {
    await this.prisma.user.update({
      where: { id },
      data: { passwordHash, tokenVersion: { increment: 1 } },
    });
  }
}

export class InMemoryUserRepository implements UserRepository {
  private readonly users = new Map<UUID, User>();

  async findByEmail(email: string) {
    return [...this.users.values()].find(u => u.email === email) ?? null;
  }

  async findById(id: UUID) {
    return this.users.get(id) ?? null;
  }

  async create(data: { email: string; passwordHash: string; role?: Role }) {
    const now = new Date();
    const user: User = { id: randomUUID(), role: "USER", tokenVersion: 0, createdAt: now, updatedAt: now, ...data };
    this.users.set(user.id, user);
    return user;
  }

  async updatePassword(id: UUID, passwordHash: string) {
    const user = this.users.get(id);
    if (user) {
      user.passwordHash = passwordHash;
      user.tokenVersion += 1;
      user.updatedAt = new Date();
    }
  }
}
