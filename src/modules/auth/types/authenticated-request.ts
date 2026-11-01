import type { Request } from 'express';

export interface AuthenticatedUser {
  userId: number;
}

export interface AuthenticatedRequest extends Request {
  user: AuthenticatedUser;
}
