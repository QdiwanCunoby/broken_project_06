// Configurazione Express app + composition root — separata da index.ts per i test (Giorno 7)
import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { PrismaClient } from "@prisma/client";
import { env } from "./config/env";
import { requestId } from "./middleware/requestId";
import { requestLogger } from "./middleware/requestLogger";
import { notFoundHandler } from "./middleware/notFoundHandler";
import { errorHandler } from "./middleware/errorHandler";
import { createAuthenticate } from "./middleware/authenticate";
import { PrismaUserRepository, UserRepository } from "./modules/auth/auth.repository";
import { AuthService } from "./modules/auth/auth.service";
import { AuthController } from "./modules/auth/auth.controller";
import { createAuthRoutes } from "./modules/auth/auth.routes";
import { PrismaAccountRepository } from "./modules/account/account.repository";
import { AccountService } from "./modules/account/account.service";
import { AccountController } from "./modules/account/account.controller";
import { createAccountRoutes } from "./modules/account/account.routes";
import { PrismaCustomerRepository } from "./modules/customer/customer.repository";
import { CustomerService } from "./modules/customer/customer.service";
import { CustomerController } from "./modules/customer/customer.controller";
import { createCustomerRoutes } from "./modules/customer/customer.routes";
import { PrismaTransferRepository } from "./modules/transfer/transfer.repository";
import { TransferService } from "./modules/transfer/transfer.service";
import { TransferController } from "./modules/transfer/transfer.controller";
import { createTransferRoutes } from "./modules/transfer/transfer.routes";

// ─── Composition root: Repository → Service → Controller → Routes ───
// UN SOLO PrismaClient (un pool di connessioni), passato a tutti i repository
const prisma = new PrismaClient();

// Dall'in-memory a Postgres si cambia solo la riga del repository (InMemoryAccountRepository() → PrismaAccountRepository(prisma)):
// Service e Controller non sanno dove stanno i dati.
const accountRepository = new PrismaAccountRepository(prisma);
const accountService = new AccountService(accountRepository);
const accountController = new AccountController(accountService);
const accountRoutes = createAccountRoutes(accountController);

const customerRepository = new PrismaCustomerRepository(prisma);
const customerService = new CustomerService(customerRepository);
const customerController = new CustomerController(customerService);
const customerRoutes = createCustomerRoutes(customerController);

const transferRepository = new PrismaTransferRepository(prisma);
const transferService = new TransferService(prisma, transferRepository);   // apre lui la $transaction
const transferController = new TransferController(transferService);
const transferRoutes = createTransferRoutes(transferController);


// Factory: i test passano un InMemoryUserRepository, la produzione usa Prisma (nessun DB richiesto per i test di auth)
export const createApp = (userRepository: UserRepository = new PrismaUserRepository(prisma)) => {
  const authService = new AuthService(userRepository);
  const authController = new AuthController(authService);
  const authenticate = createAuthenticate(authService);
  const authRoutes = createAuthRoutes(authController, authenticate);

  const app = express();

  // ─── Pipeline middleware (l'ordine conta: ogni richiesta li attraversa dall'alto in basso) ───
  app.use(requestId);                                                        // 1. req.id + header X-Request-Id
  app.use(requestLogger);                                                    // 2. pino-http: log con reqId, status, ms
  app.use(helmet());                                                         // 3. Security headers
  app.use(cors({ origin: env.corsOrigin.split(","), credentials: true, exposedHeaders: ["X-Request-Id"] })); // 4. CORS
  app.use(express.json({ limit: "100kb" }));                                 // 5. Parse body JSON → req.body
  app.use(cookieParser());                                                   // 6. Parse cookie → req.cookies

  // ─── Routes (authenticate PRIMA delle route che protegge: Express applica i middleware in ordine di registrazione) ───
  app.use("/api/auth", authRoutes);                                          // pubbliche (change-password protegge se stessa)
  app.use("/api/accounts", authenticate, accountRoutes);                     // protette
  app.use("/api/customers", authenticate, customerRoutes);
  app.use("/api/transfers", authenticate, transferRoutes);

  // ─── Health check ───
  app.get("/health", (req, res) => {
    res.json({ data: { status: "ok", timestamp: new Date().toISOString() } });
  });

  // ─── 404 catch-all + error handler (sempre per ultimi: errorHandler è l'ULTIMO app.use) ───
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
};

const app = createApp();

export { app, prisma };