import { Logger, UnauthorizedException } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { User } from '../../entities/user.entity';
import { HashService } from '../hash/hash.service';
import { UserRole } from '../users/user-role.enum';
import { UsersService } from '../users/users.service';
import { AuthService } from './auth.service';

describe('AuthService', () => {
  let service: AuthService;
  let usersService: {
    findCredentialsByEmail: jest.MockedFunction<
      UsersService['findCredentialsByEmail']
    >;
  };
  let hashService: {
    compare: jest.MockedFunction<HashService['compare']>;
  };

  const user: User = {
    id: 7,
    email: 'test@example.com',
    passwordHash: 'stored-password-hash',
    role: UserRole.USER,
    isEmailVerified: false,
    createdAt: new Date('2026-10-30T04:56:19.145Z'),
  };

  beforeEach(async () => {
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});

    usersService = { findCredentialsByEmail: jest.fn() };
    hashService = { compare: jest.fn() };

    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: usersService },
        { provide: HashService, useValue: hashService },
      ],
    }).compile();

    service = module.get(AuthService);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('returns only the safe profile when the password matches', async () => {
    usersService.findCredentialsByEmail.mockResolvedValue(user);
    hashService.compare.mockResolvedValue(true);

    const result = await service.login(user.email, 'correct-password');

    expect(usersService.findCredentialsByEmail).toHaveBeenCalledWith(
      user.email,
    );
    expect(hashService.compare).toHaveBeenCalledTimes(1);
    expect(hashService.compare).toHaveBeenCalledWith(
      'correct-password',
      user.passwordHash,
    );
    expect(result).toEqual({
      id: user.id,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt,
    });
    expect(result).not.toHaveProperty('passwordHash');
  });

  it('rejects a wrong password with the generic 401 response', async () => {
    usersService.findCredentialsByEmail.mockResolvedValue(user);
    hashService.compare.mockResolvedValue(false);

    const attempt = service.login(user.email, 'wrong-password');

    await expect(attempt).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(attempt).rejects.toMatchObject({
      status: 401,
      message: 'Неверный email или пароль',
    });
    expect(hashService.compare).toHaveBeenCalledTimes(1);
    expect(hashService.compare).toHaveBeenCalledWith(
      'wrong-password',
      user.passwordHash,
    );
  });

  it.each([false, true])(
    'compares a dummy hash and rejects an unknown email even when compare returns %s',
    async (matches) => {
      usersService.findCredentialsByEmail.mockResolvedValue(null);
      hashService.compare.mockResolvedValue(matches);

      const attempt = service.login(
        'unknown@example.com',
        'submitted-password',
      );

      await expect(attempt).rejects.toBeInstanceOf(UnauthorizedException);
      await expect(attempt).rejects.toMatchObject({
        status: 401,
        message: 'Неверный email или пароль',
      });
      expect(usersService.findCredentialsByEmail).toHaveBeenCalledWith(
        'unknown@example.com',
      );
      expect(hashService.compare).toHaveBeenCalledTimes(1);
      expect(hashService.compare).toHaveBeenCalledWith(
        'submitted-password',
        expect.stringMatching(/^\$2[aby]\$10\$[./A-Za-z0-9]{53}$/),
      );
    },
  );
});
