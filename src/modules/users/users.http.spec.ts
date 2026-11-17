import type { NestExpressApplication } from '@nestjs/platform-express';
import { APP_GUARD } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import request from 'supertest';
import { User } from '../../entities/user.entity';
import { AuthSession } from '../../entities/authSession.entity';
import { configureApp } from '../../configure-app';
import { HashService } from '../hash/hash.service';
import { JwtStrategy } from '../auth/strategies/jwt.strategy';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { UserRole } from './user-role.enum';

jest.mock('@nestjs/config', () => ({
  ConfigService: class ConfigService {},
}));

describe('User authorization (HTTP, real guards/service, mocked repository)', () => {
  let app: NestExpressApplication;
  let jwt: JwtService;
  let records: Map<number, User>;
  const secret = Buffer.alloc(32, 3);
  const repository = {
    find: jest.fn(),
    findOneBy: jest.fn(),
    update: jest.fn(),
  };

  function profile(user: User) {
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt.toISOString(),
      displayName: user.displayName,
    };
  }

  const sessions = { findOneBy: jest.fn() };
  function sessionId(id: number) {
    return `00000000-0000-4000-8000-${String(id).padStart(12, '0')}`;
  }

  function token(id: number) {
    return `Bearer ${jwt.sign({ sub: String(id), sid: sessionId(id) })}`;
  }

  beforeEach(async () => {
    records = new Map(
      [7, 8, 9].map((id) => [
        id,
        {
          id,
          email: `user${id}@example.com`,
          role: id === 9 ? UserRole.ADMIN : UserRole.USER,
          isEmailVerified: false,
          createdAt: new Date('2026-11-13T00:00:00.000Z'),
          displayName: null,
          // Deliberately return the secret too, to exercise the response mapper.
          passwordHash: 'must-never-be-returned',
        },
      ]),
    );
    sessions.findOneBy
      .mockReset()
      .mockImplementation(({ id }: { id: string }) => {
        const userId = [7, 8, 9].find((userId) => sessionId(userId) === id);
        return Promise.resolve(
          userId === undefined
            ? null
            : {
                id,
                userId,
                expiresAt: new Date(Date.now() + 86_400_000),
                revokedAt: null,
              },
        );
      });
    repository.find
      .mockReset()
      .mockImplementation(() => Promise.resolve([...records.values()]));
    repository.findOneBy
      .mockReset()
      .mockImplementation(({ id }: { id: number }) =>
        Promise.resolve(records.get(id) ?? null),
      );
    repository.update
      .mockReset()
      .mockImplementation(({ id }: { id: number }, patch: Partial<User>) => {
        const user = records.get(id);
        if (!user) return Promise.resolve({ affected: 0 });
        Object.assign(user, patch);
        return Promise.resolve({ affected: 1 });
      });
    const values = {
      JWT_SECRET: secret.toString('hex'),
      JWT_ISSUER: 'pet-tests',
      JWT_AUDIENCE: 'pet-api',
    };
    const module = await Test.createTestingModule({
      imports: [
        PassportModule.register({ session: false }),
        JwtModule.register({
          secret,
          signOptions: {
            algorithm: 'HS256',
            issuer: values.JWT_ISSUER,
            audience: values.JWT_AUDIENCE,
            expiresIn: 900,
          },
        }),
      ],
      controllers: [UsersController],
      providers: [
        UsersService,
        JwtStrategy,
        { provide: APP_GUARD, useClass: JwtAuthGuard },
        { provide: APP_GUARD, useClass: RolesGuard },
        { provide: getRepositoryToken(User), useValue: repository },
        { provide: getRepositoryToken(AuthSession), useValue: sessions },
        { provide: HashService, useValue: {} },
        {
          provide: ConfigService,
          useValue: {
            getOrThrow: (key: keyof typeof values) => values[key],
          },
        },
      ],
    }).compile();
    jwt = module.get(JwtService);
    app = module.createNestApplication<NestExpressApplication>();
    configureApp(app);
    await app.init();
  });

  afterEach(async () => {
    await app?.close();
  });

  it.each([undefined, 'Bearer invalid'])(
    'rejects invalid authentication before role lookup: %s',
    async (header) => {
      const attempt = request(app.getHttpServer()).get('/users');
      if (header !== undefined) attempt.set('Authorization', header);
      await attempt.expect(401);
      expect(repository.findOneBy).not.toHaveBeenCalled();
      expect(repository.find).not.toHaveBeenCalled();
    },
  );

  it('denies USER the list even when JWT claims ADMIN', async () => {
    await request(app.getHttpServer())
      .get('/users')
      .set(
        'Authorization',
        `Bearer ${jwt.sign({ sub: '7', sid: sessionId(7), role: 'ADMIN' })}`,
      )
      .expect(403);
    expect(repository.find).not.toHaveBeenCalled();
  });

  it('returns the exact safe list for ADMIN', async () => {
    await request(app.getHttpServer())
      .get('/users')
      .set('Authorization', token(9))
      .expect(200)
      .expect([...records.values()].map(profile));
  });

  it('uses current DB role with the same JWT after demotion and restoration', async () => {
    const authorization = token(9);
    await request(app.getHttpServer())
      .get('/users')
      .set('Authorization', authorization)
      .expect(200);
    records.get(9)!.role = UserRole.USER;
    repository.find.mockClear();
    await request(app.getHttpServer())
      .get('/users')
      .set('Authorization', authorization)
      .expect(403);
    expect(repository.find).not.toHaveBeenCalled();
    records.get(9)!.role = UserRole.ADMIN;
    await request(app.getHttpServer())
      .get('/users')
      .set('Authorization', authorization)
      .expect(200);
  });

  it('returns only safe fields for an owner and for ADMIN reading another profile', async () => {
    for (const requester of [7, 9]) {
      await request(app.getHttpServer())
        .get('/users/7')
        .set('Authorization', token(requester))
        .expect(200)
        .expect(profile(records.get(7)!));
    }
  });

  it('hides existing and missing foreign profiles identically without loading them', async () => {
    for (const id of [8, 999]) {
      repository.findOneBy.mockClear();
      await request(app.getHttpServer())
        .get(`/users/${id}`)
        .set('Authorization', token(7))
        .expect(404)
        .expect({
          message: 'User not found',
          error: 'Not Found',
          statusCode: 404,
        });
      expect(repository.findOneBy).toHaveBeenCalledTimes(2);
      expect(repository.findOneBy).toHaveBeenCalledWith({ id: 7 });
    }
  });

  it('returns 404 for ADMIN reading a missing profile', async () => {
    await request(app.getHttpServer())
      .get('/users/999')
      .set('Authorization', token(9))
      .expect(404);
  });

  it.each([7, 9])(
    'allows user %s to update only their own display name',
    async (id) => {
      const before = { ...records.get(id)! };
      await request(app.getHttpServer())
        .patch(`/users/${id}`)
        .set('Authorization', token(id))
        .send({ displayName: '  Александр  ' })
        .expect(200)
        .expect({ ...profile(before), displayName: 'Александр' });
      expect(repository.update).toHaveBeenCalledWith(
        { id },
        { displayName: 'Александр' },
      );
      expect(records.get(id)).toEqual({ ...before, displayName: 'Александр' });
      await request(app.getHttpServer())
        .get(`/users/${id}`)
        .set('Authorization', token(id))
        .expect(200)
        .expect({ ...profile(before), displayName: 'Александр' });
    },
  );

  it.each([7, 9])(
    'denies user %s editing another profile without writing',
    async (id) => {
      const before = { ...records.get(8)! };
      await request(app.getHttpServer())
        .patch('/users/8')
        .set('Authorization', token(id))
        .send({ displayName: 'Changed' })
        .expect(404);
      expect(repository.update).not.toHaveBeenCalled();
      expect(records.get(8)).toEqual(before);
    },
  );

  it.each(['role', 'id', 'isEmailVerified', 'requesterId', 'passwordHash'])(
    'rejects extra field %s without changing any profile data',
    async (field) => {
      const before = { ...records.get(7)! };
      await request(app.getHttpServer())
        .patch('/users/7')
        .set('Authorization', token(7))
        .send({ displayName: 'Changed', [field]: 'injected' })
        .expect(400);
      expect(repository.update).not.toHaveBeenCalled();
      expect(records.get(7)).toEqual(before);
    },
  );

  it.each([
    {},
    { displayName: null },
    { displayName: 123 },
    { displayName: '   ' },
    { displayName: 'a'.repeat(81) },
  ])('rejects invalid update body %j', async (body) => {
    await request(app.getHttpServer())
      .patch('/users/7')
      .set('Authorization', token(7))
      .send(body)
      .expect(400);
    expect(repository.update).not.toHaveBeenCalled();
  });

  it('accepts a display name at the 80 character limit', async () => {
    await request(app.getHttpServer())
      .patch('/users/7')
      .set('Authorization', token(7))
      .send({ displayName: 'a'.repeat(80) })
      .expect(200);
  });

  it.each(['get', 'patch'] as const)(
    'protects %s profile without a token',
    async (method) => {
      await request(app.getHttpServer())
        [method]('/users/7')
        .send({ displayName: 'Changed' })
        .expect(401);
      expect(repository.findOneBy).not.toHaveBeenCalled();
      expect(repository.update).not.toHaveBeenCalled();
    },
  );

  it.each(['get', 'patch'] as const)(
    'rejects invalid ID on %s',
    async (method) => {
      await request(app.getHttpServer())
        [method]('/users/abc')
        .set('Authorization', token(7))
        .send({ displayName: 'Changed' })
        .expect(400);
      expect(repository.findOneBy).toHaveBeenCalledTimes(1);
      expect(repository.findOneBy).toHaveBeenCalledWith({ id: 7 });
      expect(repository.update).not.toHaveBeenCalled();
    },
  );

  it.each(['get', 'patch'] as const)(
    'rejects a deleted requester on %s',
    async (method) => {
      records.delete(7);
      await request(app.getHttpServer())
        [method]('/users/7')
        .set('Authorization', token(7))
        .send({ displayName: 'Changed' })
        .expect(401);
      expect(repository.update).not.toHaveBeenCalled();
    },
  );

  it('handles an update that no longer matches a record', async () => {
    repository.update.mockResolvedValue({ affected: 0 });
    await request(app.getHttpServer())
      .patch('/users/7')
      .set('Authorization', token(7))
      .send({ displayName: 'Changed' })
      .expect(404);
  });

  it('handles a profile deleted after the update', async () => {
    repository.update.mockImplementation(() => {
      records.delete(7);
      return Promise.resolve({ affected: 1 });
    });
    await request(app.getHttpServer())
      .patch('/users/7')
      .set('Authorization', token(7))
      .send({ displayName: 'Changed' })
      .expect(404);
  });
});
