import { Controller, Get, Req } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { APP_GUARD } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { Test } from '@nestjs/testing';
import { ThrottlerModule } from '@nestjs/throttler';
import request from 'supertest';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { HashService } from '../hash/hash.service';
import { UsersService } from '../users/users.service';
import { UserRole } from '../users/user-role.enum';
import { UsersController } from '../users/users.controller';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import type { AuthenticatedRequest } from './types/authenticated-request';
import { configureApp } from '../../configure-app';

// No auth decorators: this controller must still be protected globally.
@Controller('guard-probe')
class GuardProbeController {
  @Get()
  get(@Req() request: AuthenticatedRequest) {
    return { userId: request.user.userId };
  }
}

// Configuration is supplied explicitly; no local env or database is used.
jest.mock('@nestjs/config', () => ({
  ConfigService: class ConfigService {},
}));

describe('Global JWT authentication (HTTP, real Passport/JWT, mocked database)', () => {
  let app: NestExpressApplication;
  let jwt: JwtService;
  const secret = Buffer.alloc(32, 1);
  const users = {
    findById: jest.fn(),
    findAll: jest.fn(),
    findCredentialsByEmail: jest.fn(),
    create: jest.fn(),
  };
  const hashes = { compare: jest.fn() };
  const user = {
    id: 7,
    email: 'test@example.com',
    role: UserRole.USER,
    isEmailVerified: false,
    createdAt: new Date('2026-11-01T00:00:00.000Z'),
    displayName: null,
    passwordHash: 'must-never-be-returned',
  };

  // A fresh app also isolates the real throttler storage between tests.
  beforeEach(async () => {
    users.findById.mockReset().mockResolvedValue(user);
    users.findAll.mockReset().mockResolvedValue([]);
    users.findCredentialsByEmail.mockReset().mockResolvedValue(user);
    users.create.mockReset().mockResolvedValue({ id: user.id });
    hashes.compare.mockReset().mockResolvedValue(true);
    const values = {
      JWT_SECRET: secret.toString('hex'),
      JWT_ISSUER: 'pet-backend',
      JWT_AUDIENCE: 'pet-api',
      JWT_ACCESS_TTL_SECONDS: 900,
    };
    const module = await Test.createTestingModule({
      imports: [
        PassportModule.register({ session: false }),
        ThrottlerModule.forRoot([{ ttl: 60_000, limit: 5 }]),
        JwtModule.register({
          secret,
          signOptions: {
            algorithm: 'HS256',
            issuer: values.JWT_ISSUER,
            audience: values.JWT_AUDIENCE,
            expiresIn: values.JWT_ACCESS_TTL_SECONDS,
          },
        }),
      ],
      controllers: [AuthController, UsersController, GuardProbeController],
      providers: [
        AuthService,
        JwtStrategy,
        { provide: APP_GUARD, useClass: JwtAuthGuard },
        { provide: APP_GUARD, useClass: RolesGuard },
        { provide: UsersService, useValue: users },
        { provide: HashService, useValue: hashes },
        {
          provide: ConfigService,
          useValue: {
            getOrThrow: (key: string) => {
              if (!(key in values))
                throw new Error('Missing test configuration');
              return values[key as keyof typeof values];
            },
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
    'allows public login without a valid JWT (header: %s)',
    async (header) => {
      const attempt = request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: user.email, password: 'correct-password' });
      if (header !== undefined) attempt.set('Authorization', header);
      const response = await attempt.expect(200);
      const body = response.body as { expiresIn: number; accessToken: string };

      expect(body.expiresIn).toBe(900);
      expect(jwt.verify(body.accessToken)).toMatchObject({ sub: '7' });
      expect(hashes.compare).toHaveBeenCalledWith(
        'correct-password',
        user.passwordHash,
      );
    },
  );

  it('allows registration without a JWT in another controller', async () => {
    await request(app.getHttpServer())
      .post('/users')
      .send({ email: user.email, password: 'valid-password' })
      .expect(201)
      .expect({ id: user.id });
    expect(users.create).toHaveBeenCalledWith(user.email, 'valid-password');
  });

  it('still validates a public login request', async () => {
    await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: user.email, password: 'valid-password', role: 'ADMIN' })
      .expect(400);
    expect(users.findCredentialsByEmail).not.toHaveBeenCalled();
  });

  it('normalizes the DTO email while preserving the password', async () => {
    await request(app.getHttpServer())
      .post('/auth/login')
      .send({
        email: '  TEST@EXAMPLE.COM  ',
        password: ' password with spaces ',
      })
      .expect(200);

    expect(users.findCredentialsByEmail).toHaveBeenCalledWith(user.email);
    expect(hashes.compare).toHaveBeenCalledWith(
      ' password with spaces ',
      user.passwordHash,
    );
  });

  it('rejects JSON larger than 16kb before checking credentials', async () => {
    await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: user.email, password: 'a'.repeat(16 * 1024) })
      .expect(413);

    expect(users.findCredentialsByEmail).not.toHaveBeenCalled();
    expect(hashes.compare).not.toHaveBeenCalled();
  });

  it('still throttles public login and blocks before checking credentials', async () => {
    hashes.compare.mockResolvedValue(false);
    for (let attempt = 0; attempt < 5; attempt++) {
      await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: user.email, password: 'wrong-password' })
        .expect(401);
    }
    await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: user.email, password: 'wrong-password' })
      .expect(429);
    expect(users.findCredentialsByEmail).toHaveBeenCalledTimes(5);
    expect(hashes.compare).toHaveBeenCalledTimes(5);
  });

  it.each([undefined, 'Bearer invalid'])(
    'protects a separate controller without auth decorators (header: %s)',
    async (header) => {
      const attempt = request(app.getHttpServer()).get('/guard-probe');
      if (header !== undefined) attempt.set('Authorization', header);
      await attempt.expect(401);
    },
  );

  it('passes the verified user to a separate controller without auth decorators', async () => {
    await request(app.getHttpServer())
      .get('/guard-probe')
      .set('Authorization', `Bearer ${jwt.sign({ sub: '7' })}`)
      .expect(200)
      .expect({ userId: 7 });
  });

  it('uses the verified subject to load and return only the current safe profile', async () => {
    const token = jwt.sign({ sub: '7', role: 'ADMIN' });
    const response = await request(app.getHttpServer())
      .get('/auth/me')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(response.body).toEqual({
      id: user.id,
      email: user.email,
      role: UserRole.USER,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt.toISOString(),
      displayName: user.displayName,
    });
    expect(users.findById).toHaveBeenCalledWith(7);
    expect(users.findById).toHaveBeenCalledTimes(1);
  });

  it('returns 401 when the token is valid but the user no longer exists', async () => {
    users.findById.mockResolvedValue(null);
    await request(app.getHttpServer())
      .get('/auth/me')
      .set('Authorization', `Bearer ${jwt.sign({ sub: '7' })}`)
      .expect(401)
      .expect({ message: 'Unauthorized', statusCode: 401 });
  });

  it.each([undefined, '', 'Basic abc', 'Bearer', 'Bearer invalid'])(
    'rejects a missing or malformed Authorization header: %s',
    async (header) => {
      const attempt = request(app.getHttpServer()).get('/auth/me');
      if (header !== undefined) attempt.set('Authorization', header);
      await attempt
        .expect(401)
        .expect({ message: 'Unauthorized', statusCode: 401 });
      expect(users.findById).not.toHaveBeenCalled();
    },
  );

  it.each([
    ['wrong signature', { secret: Buffer.alloc(32, 2) }],
    ['wrong issuer', { issuer: 'another-backend' }],
    ['wrong audience', { audience: 'another-api' }],
    ['expired token', { expiresIn: -60 }],
    ['future nbf', { notBefore: 60 }],
    ['disallowed algorithm', { algorithm: 'HS384' as const }],
  ])('rejects %s', async (_name, options) => {
    await request(app.getHttpServer())
      .get('/auth/me')
      .set('Authorization', `Bearer ${jwt.sign({ sub: '7' }, options)}`)
      .expect(401)
      .expect({ message: 'Unauthorized', statusCode: 401 });
    expect(users.findById).not.toHaveBeenCalled();
  });

  it.each([undefined, 7, '0', '-1', 'abc', '07', '9007199254740992'])(
    'rejects an invalid subject: %s',
    async (sub) => {
      await request(app.getHttpServer())
        .get('/auth/me')
        .set('Authorization', `Bearer ${jwt.sign({ sub })}`)
        .expect(401)
        .expect({ message: 'Unauthorized', statusCode: 401 });
      expect(users.findById).not.toHaveBeenCalled();
    },
  );

  it('requires exp even for an otherwise valid signed token', async () => {
    const token = new JwtService({ secret }).sign({
      sub: '7',
      iss: 'pet-backend',
      aud: 'pet-api',
    });
    await request(app.getHttpServer())
      .get('/auth/me')
      .set('Authorization', `Bearer ${token}`)
      .expect(401)
      .expect({ message: 'Unauthorized', statusCode: 401 });
    expect(users.findById).not.toHaveBeenCalled();
  });

  it.each(['tampered', 'unsigned'])('rejects a %s token', async (kind) => {
    const parts = jwt.sign({ sub: '7' }).split('.');
    if (kind === 'tampered') {
      parts[1] = Buffer.from(JSON.stringify({ sub: '8' })).toString(
        'base64url',
      );
    } else {
      parts[0] = Buffer.from(
        JSON.stringify({ alg: 'none', typ: 'JWT' }),
      ).toString('base64url');
      parts[2] = '';
    }
    await request(app.getHttpServer())
      .get('/auth/me')
      .set('Authorization', `Bearer ${parts.join('.')}`)
      .expect(401)
      .expect({ message: 'Unauthorized', statusCode: 401 });
    expect(users.findById).not.toHaveBeenCalled();
  });
});
