import type { INestApplication } from '@nestjs/common';
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

// Configuration is supplied explicitly; no local env or database is used.
jest.mock('@nestjs/config', () => ({
  ConfigService: class ConfigService {},
}));

describe('GET /auth/me (HTTP, real Passport/JWT, mocked database)', () => {
  let app: INestApplication;
  let jwt: JwtService;
  const secret = Buffer.alloc(32, 1);
  const users = { findById: jest.fn() };
  const user = {
    id: 7,
    email: 'test@example.com',
    role: UserRole.USER,
    isEmailVerified: false,
    createdAt: new Date('2026-11-01T00:00:00.000Z'),
    passwordHash: 'must-never-be-returned',
  };

  beforeAll(async () => {
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
      controllers: [AuthController],
      providers: [
        AuthService,
        JwtStrategy,
        { provide: UsersService, useValue: users },
        { provide: HashService, useValue: {} },
        {
          provide: ConfigService,
          useValue: {
            getOrThrow: (key: string) => {
              if (!(key in values))
                throw new Error('Missing test configuration');
              return values[key];
            },
          },
        },
      ],
    }).compile();
    jwt = module.get(JwtService);
    app = module.createNestApplication();
    await app.init();
  });

  beforeEach(() => {
    users.findById.mockReset().mockResolvedValue(user);
  });

  afterAll(async () => {
    await app?.close();
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
    });
    expect(users.findById).toHaveBeenCalledWith(7);
    expect(users.findById).toHaveBeenCalledTimes(1);
  });

  it('returns 401 when the token is valid but the user no longer exists', async () => {
    users.findById.mockResolvedValue(null);
    await request(app.getHttpServer())
      .get('/auth/me')
      .set('Authorization', `Bearer ${jwt.sign({ sub: '7' })}`)
      .expect(401);
  });

  it.each([undefined, '', 'Basic abc', 'Bearer', 'Bearer invalid'])(
    'rejects a missing or malformed Authorization header: %s',
    async (header) => {
      const attempt = request(app.getHttpServer()).get('/auth/me');
      if (header !== undefined) attempt.set('Authorization', header);
      await attempt.expect(401);
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
      .expect(401);
    expect(users.findById).not.toHaveBeenCalled();
  });

  it.each([undefined, 7, '0', '-1', 'abc', '07', '9007199254740992'])(
    'rejects an invalid subject: %s',
    async (sub) => {
      await request(app.getHttpServer())
        .get('/auth/me')
        .set('Authorization', `Bearer ${jwt.sign({ sub })}`)
        .expect(401);
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
      .expect(401);
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
      .expect(401);
    expect(users.findById).not.toHaveBeenCalled();
  });
});
