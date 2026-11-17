import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthenticatedUser } from '../types/authenticated-request';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthSession } from '../../../entities/authSession.entity';
import { Repository } from 'typeorm';
import { UsersService } from '../../users/users.service';
import { isUUID } from 'class-validator';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    config: ConfigService,
    @InjectRepository(AuthSession)
    private readonly authRepository: Repository<AuthSession>,
    private readonly userService: UsersService,
  ) {
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

  async validate(payload: unknown): Promise<AuthenticatedUser> {
    if (
      typeof payload !== 'object' ||
      payload === null ||
      Array.isArray(payload)
    ) {
      throw new UnauthorizedException();
    }

    const { sub, exp, sid } = payload as Record<string, unknown>;

    if (
      typeof sub !== 'string' ||
      !/^[1-9]\d*$/.test(sub) ||
      !Number.isSafeInteger(Number(sub)) ||
      typeof exp !== 'number' ||
      !Number.isFinite(exp) ||
      typeof sid !== 'string' ||
      !isUUID(sid, '4')
    ) {
      throw new UnauthorizedException();
    }

    const session = await this.authRepository.findOneBy({ id: sid });

    if (
      !session ||
      session.userId !== Number(sub) ||
      session.revokedAt !== null ||
      session.expiresAt.getTime() <= Date.now()
    ) {
      throw new UnauthorizedException();
    }

    const user = await this.userService.findById(session.userId);

    if (!user) {
      throw new UnauthorizedException();
    }

    return {
      userId: user.id,
      sessionId: session.id,
    };
  }
}
