import { Injectable, UnauthorizedException } from '@nestjs/common';
import type { UserResponse } from '../../entities/user.entity';
import { HashService } from '../hash/hash.service';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UsersService,
    private readonly hashService: HashService,
  ) {}

  async login(email: string, password: string): Promise<UserResponse> {
    const user = await this.userService.findCredentialsByEmail(email);

    if (!user) {
      throw new UnauthorizedException('Неверный email или пароль');
    }
    const isPasswordMatching = await this.hashService.compare(
      password,
      user.passwordHash,
    );
    if (!isPasswordMatching) {
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
