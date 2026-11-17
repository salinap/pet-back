import { Logger, UnauthorizedException } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { getRepositoryToken } from '@nestjs/typeorm';
import { IsNull } from 'typeorm';
import { AuthSession } from '../../entities/authSession.entity';
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
  let log: jest.SpyInstance;
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
  let sessions: {
    save: jest.Mock<Promise<Partial<AuthSession>>, [Partial<AuthSession>]>;
    update: jest.Mock<Promise<{ affected: number }>, [object, object]>;
  };
  const sessionId = '26b9e2cc-a2ef-4df1-92a8-374954b1348b';

  const user: User = {
    id: 7,
    email: 'test@example.com',
    passwordHash: 'stored-password-hash',
    role: UserRole.USER,
    isEmailVerified: false,
    createdAt: new Date('2026-10-30T04:56:19.145Z'),
    displayName: null,
  };

  beforeEach(async () => {
    log = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});

    usersService = { findCredentialsByEmail: jest.fn(), findById: jest.fn() };
    hashService = { compare: jest.fn() };
    jwtService = {
      signAsync: jest
        .fn<Promise<string>, [object]>()
        .mockResolvedValue('signed-access-token'),
    };
    configService = {
      getOrThrow: jest.fn<number, [string]>().mockReturnValue(900),
    };
    sessions = {
      update: jest
        .fn<Promise<{ affected: number }>, [object, object]>()
        .mockResolvedValue({ affected: 1 }),
      save: jest
        .fn<Promise<Partial<AuthSession>>, [Partial<AuthSession>]>()
        .mockImplementation((session: Partial<AuthSession>) =>
          Promise.resolve({ ...session, id: sessionId }),
        ),
    };

    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: getRepositoryToken(AuthSession), useValue: sessions },
        { provide: UsersService, useValue: usersService },
        { provide: HashService, useValue: hashService },
        { provide: JwtService, useValue: jwtService },
        { provide: ConfigService, useValue: configService },
      ],
    }).compile();

    service = module.get(AuthService);
    log.mockClear();
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  it('revokes only the current user session when it is not already revoked', async () => {
    const now = new Date('2026-11-17T10:00:00Z');
    jest.useFakeTimers({ now });

    await expect(service.logout(user.id, sessionId)).resolves.toBeUndefined();
    expect(sessions.update).toHaveBeenCalledTimes(1);
    expect(sessions.update).toHaveBeenCalledWith(
      { id: sessionId, userId: user.id, revokedAt: IsNull() },
      { revokedAt: now },
    );
    expect(sessions.save).not.toHaveBeenCalled();
  });

  it('allows a no-op logout when the session was concurrently revoked or removed', async () => {
    sessions.update.mockResolvedValue({ affected: 0 });
    await expect(service.logout(user.id, sessionId)).resolves.toBeUndefined();
    expect(sessions.save).not.toHaveBeenCalled();
  });

  it('propagates logout persistence errors', async () => {
    const error = new Error('Database unavailable');
    sessions.update.mockRejectedValue(error);
    await expect(service.logout(user.id, sessionId)).rejects.toBe(error);
  });

  it('loads a fresh profile and excludes credentials from the response', async () => {
    usersService.findById.mockResolvedValue(user);

    await expect(service.getProfile(user.id)).resolves.toEqual({
      id: user.id,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt,
      displayName: user.displayName,
    });
    expect(usersService.findById).toHaveBeenCalledWith(user.id);
  });

  it('rejects a profile request for a deleted or missing user', async () => {
    usersService.findById.mockResolvedValue(null);

    await expect(service.getProfile(7)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('saves a 24-hour session and signs its ID with the user subject', async () => {
    const now = new Date('2026-11-17T10:00:00Z');
    jest.useFakeTimers({ now });
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
    expect(sessions.save).toHaveBeenCalledTimes(1);
    expect(sessions.save).toHaveBeenCalledWith({
      userId: user.id,
      expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000),
      revokedAt: null,
    });
    expect(jwtService.signAsync).toHaveBeenCalledWith({
      sub: '7',
      sid: sessionId,
    });
    expect(configService.getOrThrow).toHaveBeenCalledWith(
      'JWT_ACCESS_TTL_SECONDS',
    );
    expect(result).toEqual({
      accessToken: 'signed-access-token',
      expiresIn: 600,
    });
    expect(log).toHaveBeenCalledWith({
      event: 'auth.login',
      outcome: 'success',
      userId: user.id,
    });
  });

  it('waits for the session to be saved before signing a token', async () => {
    usersService.findCredentialsByEmail.mockResolvedValue(user);
    hashService.compare.mockResolvedValue(true);
    let releaseSave!: (session: Partial<AuthSession>) => void;
    let notifySaveStarted!: () => void;
    const saveStarted = new Promise<void>((resolve) => {
      notifySaveStarted = resolve;
    });
    const saved = new Promise<Partial<AuthSession>>((resolve) => {
      releaseSave = resolve;
    });
    sessions.save.mockImplementation(() => {
      notifySaveStarted();
      return saved;
    });

    const attempt = service.login(user.email, 'correct-password');
    await saveStarted;
    expect(jwtService.signAsync).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();

    releaseSave({ id: sessionId });
    await attempt;
    expect(jwtService.signAsync).toHaveBeenCalledWith({
      sub: '7',
      sid: sessionId,
    });
  });

  it('propagates a save failure without signing a token or logging success', async () => {
    usersService.findCredentialsByEmail.mockResolvedValue(user);
    hashService.compare.mockResolvedValue(true);
    const error = new Error('Database unavailable');
    sessions.save.mockRejectedValue(error);

    await expect(service.login(user.email, 'correct-password')).rejects.toBe(
      error,
    );
    expect(jwtService.signAsync).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('propagates a signing failure without logging a successful login', async () => {
    usersService.findCredentialsByEmail.mockResolvedValue(user);
    hashService.compare.mockResolvedValue(true);
    const error = new Error('Signing failed');
    jwtService.signAsync.mockRejectedValue(error);

    await expect(service.login(user.email, 'correct-password')).rejects.toBe(
      error,
    );
    expect(log).not.toHaveBeenCalled();
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
    expect(sessions.save).not.toHaveBeenCalled();
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
      expect(sessions.save).not.toHaveBeenCalled();
    },
  );
});
