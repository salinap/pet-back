import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthenticatedUser } from '../types/authenticated-request';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: Buffer.from(config.getOrThrow<string>('JWT_SECRET'), 'hex'),
      algorithms: ['HS256'],
      issuer: config.getOrThrow<string>('JWT_ISSUER'),
      audience: config.getOrThrow<string>('JWT_AUDIENCE'),
      ignoreExpiration: false,
      jsonWebTokenOptions: {
        clockTolerance: 5,
      },
    });
  }

  validate(payload: unknown): AuthenticatedUser {
    if (
      typeof payload !== 'object' ||
      payload === null ||
      Array.isArray(payload)
    ) {
      throw new UnauthorizedException();
    }

    const { sub, exp } = payload as Record<string, unknown>;

    if (
      typeof sub !== 'string' ||
      !/^[1-9]\d*$/.test(sub) ||
      !Number.isSafeInteger(Number(sub)) ||
      typeof exp !== 'number' ||
      !Number.isFinite(exp)
    ) {
      throw new UnauthorizedException();
    }

    return { userId: Number(sub) };
  }
}
