// Controller: converte HTTP ↔ business logic (cookie inclusi). Nessuna logica né try/catch.
import { Request, Response } from "express";
import { AuthService } from "./auth.service";
import { REFRESH_COOKIE, clearAuthCookies, setAuthCookies } from "./auth.cookies";
import { asyncHandler } from "../../utils/asyncHandler";
import { ok } from "../../utils/apiResponse";
import { UnauthorizedError } from "../../utils/errors";

export class AuthController {
  constructor(private readonly service: AuthService) {}

  register = asyncHandler(async (req: Request, res: Response) => {
    const user = await this.service.register(req.body);
    res.status(201).json(ok(user));
  });

  login = asyncHandler(async (req: Request, res: Response) => {
    const { user, accessToken, refreshToken } = await this.service.login(req.body);
    setAuthCookies(res, accessToken, refreshToken);   // httpOnly + secure(prod) + sameSite lax
    res.json(ok(user));
  });

  refresh = asyncHandler(async (req: Request, res: Response) => {
    const token = req.cookies?.[REFRESH_COOKIE];
    if (typeof token !== "string" || !token) throw new UnauthorizedError();
    const { accessToken, refreshToken } = await this.service.refresh(token);
    setAuthCookies(res, accessToken, refreshToken);
    res.status(204).send();
  });

  logout = asyncHandler(async (_req: Request, res: Response) => {
    clearAuthCookies(res);
    res.status(204).send();
  });

  changePassword = asyncHandler(async (req: Request, res: Response) => {
    await this.service.changePassword(req.user!.id, req.body);
    clearAuthCookies(res);   // la sessione corrente è invalidata: il frontend deve rifare login
    res.status(204).send();
  });
}
