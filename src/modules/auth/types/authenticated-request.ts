import type { Request } from 'express';

export interface AuthenticatedUser {
  userId: number;
  sessionId: string;
}

export interface AuthenticatedRequest extends Request {
  user: AuthenticatedUser;
}
