import { Injectable, UnauthorizedException } from '@nestjs/common';
import type { UserResponse } from '../../entities/user.entity';
import { HashService } from '../hash/hash.service';
import { UsersService } from '../users/users.service';

const DUMMY_PASSWORD_HASH =
  '$2b$10$D/b28TkYUJH/jqBU7b9VvuhI7tExaIukEEwV51RY/pBdNf6JGgpf2';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UsersService,
    private readonly hashService: HashService,
  ) {}

  async login(email: string, password: string): Promise<UserResponse> {
    const user = await this.userService.findCredentialsByEmail(email);

    const hashToCompare = user ? user.passwordHash : DUMMY_PASSWORD_HASH;
    const isPasswordMatching = await this.hashService.compare(
      password,
      hashToCompare,
    );
    if (!user || !isPasswordMatching) {
      throw new UnauthorizedException('Неверный email или пароль');
    }

    return {
      id: user.id,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt,
    };
  }
}
