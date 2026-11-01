import { Logger, UnauthorizedException } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import type { User } from '../../entities/user.entity';
import { HashService } from '../hash/hash.service';
import { UserRole } from '../users/user-role.enum';
import { UsersService } from '../users/users.service';
import { AuthService } from './auth.service';

// Keep this unit suite independent of the config package's ESM loader.
jest.mock('@nestjs/config', () => ({
  ConfigService: class ConfigService {},
}));

describe('AuthService', () => {
  let service: AuthService;
  let usersService: {
    findById: jest.MockedFunction<UsersService['findById']>;
    findCredentialsByEmail: jest.MockedFunction<
      UsersService['findCredentialsByEmail']
    >;
  };
  let hashService: {
    compare: jest.MockedFunction<HashService['compare']>;
  };
  let jwtService: { signAsync: jest.Mock<Promise<string>, [object]> };
  let configService: { getOrThrow: jest.Mock<number, [string]> };

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

    usersService = { findCredentialsByEmail: jest.fn(), findById: jest.fn() };
    hashService = { compare: jest.fn() };
    jwtService = {
      signAsync: jest.fn().mockResolvedValue('signed-access-token'),
    };
    configService = { getOrThrow: jest.fn().mockReturnValue(900) };

    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: usersService },
        { provide: HashService, useValue: hashService },
        { provide: JwtService, useValue: jwtService },
        { provide: ConfigService, useValue: configService },
      ],
    }).compile();

    service = module.get(AuthService);
    jest.mocked(Logger.prototype.log).mockClear();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('loads a fresh profile and excludes credentials from the response', async () => {
    usersService.findById.mockResolvedValue(user);

    await expect(service.getProfile(user.id)).resolves.toEqual({
      id: user.id,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt,
    });
    expect(usersService.findById).toHaveBeenCalledWith(user.id);
  });

  it('rejects a profile request for a deleted or missing user', async () => {
    usersService.findById.mockResolvedValue(null);

    await expect(service.getProfile(7)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('signs only the user subject and returns the token with its configured lifetime', async () => {
    usersService.findCredentialsByEmail.mockResolvedValue(user);
    hashService.compare.mockResolvedValue(true);
    configService.getOrThrow.mockReturnValue(600);

    const result = await service.login(user.email, 'correct-password');

    expect(usersService.findCredentialsByEmail).toHaveBeenCalledWith(
      user.email,
    );
    expect(hashService.compare).toHaveBeenCalledTimes(1);
    expect(hashService.compare).toHaveBeenCalledWith(
      'correct-password',
      user.passwordHash,
    );
    expect(jwtService.signAsync).toHaveBeenCalledTimes(1);
    expect(jwtService.signAsync).toHaveBeenCalledWith({ sub: '7' });
    expect(configService.getOrThrow).toHaveBeenCalledWith(
      'JWT_ACCESS_TTL_SECONDS',
    );
    expect(result).toEqual({
      accessToken: 'signed-access-token',
      expiresIn: 600,
    });
    expect(Logger.prototype.log).toHaveBeenCalledWith({
      event: 'auth.login',
      outcome: 'success',
      userId: user.id,
    });
  });

  it('propagates a signing failure without logging a successful login', async () => {
    usersService.findCredentialsByEmail.mockResolvedValue(user);
    hashService.compare.mockResolvedValue(true);
    const error = new Error('Signing failed');
    jwtService.signAsync.mockRejectedValue(error);

    await expect(service.login(user.email, 'correct-password')).rejects.toBe(
      error,
    );
    expect(Logger.prototype.log).not.toHaveBeenCalled();
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
    expect(jwtService.signAsync).not.toHaveBeenCalled();
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
      expect(jwtService.signAsync).not.toHaveBeenCalled();
    },
  );
});
