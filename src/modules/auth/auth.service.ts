import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { HashService } from '../hash/hash.service';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserResponse } from '../../entities/user.entity';

const DUMMY_PASSWORD_HASH =
  '$2b$10$D/b28TkYUJH/jqBU7b9VvuhI7tExaIukEEwV51RY/pBdNf6JGgpf2';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    private readonly userService: UsersService,
    private readonly hashService: HashService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async getProfile(userId: number): Promise<UserResponse> {
    const user = await this.userService.findById(userId);

    if (!user) {
      throw new UnauthorizedException();
    }

    return {
      id: user.id,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt,
    };
  }

  async login(
    email: string,
    password: string,
  ): Promise<{ accessToken: string; expiresIn: number }> {
    const user = await this.userService.findCredentialsByEmail(email);

    const hashToCompare = user ? user.passwordHash : DUMMY_PASSWORD_HASH;
    const isPasswordMatching = await this.hashService.compare(
      password,
      hashToCompare,
    );
    if (!user || !isPasswordMatching) {
      this.logger.warn({
        event: 'auth.login',
        outcome: 'failure',
        reason: 'invalid_credentials',
      });
      throw new UnauthorizedException('Неверный email или пароль');
    }

    const accessToken = await this.jwtService.signAsync({
      sub: String(user.id),
    });
    const expiresIn = this.configService.getOrThrow<number>(
      'JWT_ACCESS_TTL_SECONDS',
    );

    this.logger.log({
      event: 'auth.login',
      outcome: 'success',
      userId: user.id,
    });

    return {
      accessToken,
      expiresIn,
    };
  }
}
