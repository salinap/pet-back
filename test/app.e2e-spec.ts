import { fork, spawnSync, type ChildProcess } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from 'pg';
import * as bcrypt from 'bcrypt';
import request from 'supertest';

it.each(['DB_NAME', 'DB_HOST', 'DB_PORT'])(
  'refuses unsafe %s before importing the application or connecting to a DB',
  (key) => {
    const result = spawnSync(
      process.execPath,
      [join(__dirname, 'e2e-server.cjs')],
      {
        env: {
          NODE_ENV: 'test',
          DB_HOST: '127.0.0.1',
          DB_PORT: '5434',
          DB_USER: 'pet_test',
          DB_PASSWORD: 'pet_test_password',
          DB_NAME: 'pet_test',
          [key]: 'unsafe',
        },
        encoding: 'utf8',
        timeout: 3000,
      },
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`Unsafe e2e configuration: ${key}`);
  },
);

describe('register → login → me (e2e, real PostgreSQL)', () => {
  let server: ChildProcess | undefined;
  let cwd: string | undefined;
  let url: string;
  let database: Client;
  let connected = false;
  const emails: string[] = [];
  const password = 'valid-e2e-password';

  function newEmail() {
    const email = `e2e-${randomUUID()}@example.com`;
    emails.push(email);
    return email;
  }

  beforeAll(async () => {
    // Empty cwd prevents reading the project's personal .env.
    cwd = mkdtempSync(join(tmpdir(), 'pet-e2e-'));
    server = fork(join(__dirname, 'e2e-server.cjs'), [], {
      cwd,
      execArgv: [],
      env: {
        NODE_ENV: 'test',
        DB_HOST: '127.0.0.1',
        DB_PORT: '5434',
        DB_USER: 'pet_test',
        DB_PASSWORD: 'pet_test_password',
        DB_NAME: 'pet_test',
        PORT: '4000',
        JWT_SECRET: randomBytes(32).toString('hex'),
        JWT_ISSUER: 'pet-e2e',
        JWT_AUDIENCE: 'pet-e2e-api',
        JWT_ACCESS_TTL_SECONDS: '900',
      },
      stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    });
    const child = server;
    url = await new Promise<string>((resolve, reject) => {
      let stderr = '';
      const timer = setTimeout(() => {
        reject(new Error(`E2e server startup timed out. ${stderr}`));
      }, 15_000);
      child.stderr?.on('data', (data: Buffer) => {
        stderr = (stderr + data.toString()).slice(-4000);
      });
      child.once('message', (message: { url: string }) => {
        clearTimeout(timer);
        resolve(message.url);
      });
      child.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.once('exit', (code) => {
        clearTimeout(timer);
        reject(new Error(`E2e server exited (${code}). ${stderr}`));
      });
    });
    database = new Client({
      host: '127.0.0.1',
      port: 5434,
      user: 'pet_test',
      password: 'pet_test_password',
      database: 'pet_test',
      connectionTimeoutMillis: 3000,
    });
    await database.connect();
    connected = true;
  }, 20_000);

  afterAll(async () => {
    try {
      if (connected) {
        // Delete only this run's users, never truncate the database.
        await database.query(
          'DELETE FROM users WHERE email = ANY($1::text[])',
          [emails],
        );
      }
    } finally {
      await database?.end();
      if (server && server.exitCode === null && server.signalCode === null) {
        const child = server;
        await new Promise<void>((resolve) => {
          const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
          child.once('exit', () => {
            clearTimeout(timer);
            resolve();
          });
          child.kill('SIGTERM');
        });
      }
      if (cwd) rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('persists a password hash, issues a JWT and returns only the safe profile', async () => {
    const email = newEmail();
    const registration = await request(url)
      .post('/users')
      .send({ email: `  ${email.toUpperCase()}  `, password })
      .expect(201);
    const profile = registration.body as {
      id: number;
      email: string;
      role: string;
      isEmailVerified: boolean;
      createdAt: string;
      displayName: string | null;
    };
    expect(profile).toEqual({
      id: expect.any(Number) as unknown,
      email,
      role: 'USER',
      isEmailVerified: false,
      displayName: null,
      createdAt: expect.any(String) as unknown,
    });
    const { rows } = await database.query<{ id: number; passwordHash: string }>(
      'SELECT id, "passwordHash" FROM users WHERE email = $1',
      [email],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(profile.id);
    expect(rows[0].passwordHash).not.toBe(password);
    expect(await bcrypt.compare(password, rows[0].passwordHash)).toBe(true);

    const login = await request(url)
      .post('/auth/login')
      .send({ email, password })
      .expect(200);
    const tokens = login.body as { accessToken: string; expiresIn: number };
    expect(tokens).toEqual({
      accessToken: expect.any(String) as unknown,
      expiresIn: 900,
    });
    await request(url)
      .get('/auth/me')
      .set('Authorization', `Bearer ${tokens.accessToken}`)
      .expect(200)
      .expect(profile);
    await request(url)
      .post('/auth/login')
      .send({ email, password: 'wrong-password' })
      .expect(401);
  });

  it('creates independent sessions and enforces their owner, revocation, expiry and existence', async () => {
    const email = newEmail();
    const registration = await request(url)
      .post('/users')
      .send({ email, password })
      .expect(201);
    const userId = (registration.body as { id: number }).id;
    const before = Date.now();
    const sessionIds: string[] = [];
    const tokens: string[] = [];

    for (let i = 0; i < 2; i++) {
      const login = await request(url)
        .post('/auth/login')
        .send({ email, password })
        .expect(200);
      const { accessToken } = login.body as { accessToken: string };
      tokens.push(accessToken);
      // Decode only to correlate the claim with the database record.
      const payload = JSON.parse(
        Buffer.from(accessToken.split('.')[1], 'base64url').toString('utf8'),
      ) as { sub: string; sid: string };
      expect(payload.sub).toBe(String(userId));
      expect(payload.sid).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
      sessionIds.push(payload.sid);
      await request(url)
        .get('/auth/me')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);
    }
    const after = Date.now();
    expect(sessionIds[0]).not.toBe(sessionIds[1]);

    await request(url)
      .post('/auth/login')
      .send({ email, password: 'wrong-password' })
      .expect(401);

    const { rows } = await database.query<{
      id: string;
      userId: number;
      createdAt: Date;
      expiresAt: Date;
      revokedAt: Date | null;
    }>('SELECT * FROM auth_sessions WHERE "userId" = $1', [userId]);
    expect(rows).toHaveLength(2);
    expect(rows.map((session) => session.id).sort()).toEqual(
      [...sessionIds].sort(),
    );
    for (const session of rows) {
      expect(session.userId).toBe(userId);
      expect(session.revokedAt).toBeNull();
      expect(session.createdAt).toBeInstanceOf(Date);
      const day = 24 * 60 * 60 * 1000;
      expect(session.expiresAt.getTime()).toBeGreaterThanOrEqual(before + day);
      expect(session.expiresAt.getTime()).toBeLessThanOrEqual(after + day);
    }

    const me = (index: number, status: number) =>
      request(url)
        .get('/auth/me')
        .set('Authorization', `Bearer ${tokens[index]}`)
        .expect(status);

    // Use the original JWTs throughout: only server-side state changes.
    const logout = await request(url)
      .post('/auth/logout')
      .set('Authorization', `Bearer ${tokens[0]}`)
      .send({ userId: userId + 1, sessionId: sessionIds[1] })
      .expect(204);
    expect(logout.text).toBe('');
    const revoked = await database.query<{ revokedAt: Date }>(
      'SELECT "revokedAt" FROM auth_sessions WHERE id = $1',
      [sessionIds[0]],
    );
    expect(revoked.rows[0].revokedAt).toBeInstanceOf(Date);
    await me(0, 401);
    await me(1, 200);
    await request(url)
      .post('/auth/logout')
      .set('Authorization', `Bearer ${tokens[0]}`)
      .expect(401);
    const repeated = await database.query<{ revokedAt: Date }>(
      'SELECT "revokedAt" FROM auth_sessions WHERE id = $1',
      [sessionIds[0]],
    );
    expect(repeated.rows[0].revokedAt).toEqual(revoked.rows[0].revokedAt);
    const other = await database.query<{ revokedAt: Date | null }>(
      'SELECT "revokedAt" FROM auth_sessions WHERE id = $1',
      [sessionIds[1]],
    );
    expect(other.rows[0].revokedAt).toBeNull();

    await database.query('DELETE FROM auth_sessions WHERE id = $1', [
      sessionIds[0],
    ]);
    await me(0, 401);

    const foreignEmail = newEmail();
    const foreign = await request(url)
      .post('/users')
      .send({ email: foreignEmail, password })
      .expect(201);
    await database.query(
      'UPDATE auth_sessions SET "userId" = $1 WHERE id = $2',
      [(foreign.body as { id: number }).id, sessionIds[1]],
    );
    await me(1, 401);

    await database.query(
      'UPDATE auth_sessions SET "userId" = $1 WHERE id = $2',
      [userId, sessionIds[1]],
    );
    await me(1, 200);
    await database.query(
      'UPDATE auth_sessions SET "expiresAt" = now() - interval \'1 second\' WHERE id = $1',
      [sessionIds[1]],
    );
    await me(1, 401);

    await database.query(
      'UPDATE auth_sessions SET "expiresAt" = now() + interval \'1 day\' WHERE id = $1',
      [sessionIds[1]],
    );
    await me(1, 200);
    await database.query('DELETE FROM users WHERE id = $1', [userId]);
    const remaining = await database.query(
      'SELECT id FROM auth_sessions WHERE "userId" = $1',
      [userId],
    );
    expect(remaining.rows).toHaveLength(0);
    await me(1, 401);
  });

  it('rejects duplicate registration with a real database', async () => {
    const email = newEmail();
    await request(url).post('/users').send({ email, password }).expect(201);
    await request(url).post('/users').send({ email, password }).expect(409);
    const { rows } = await database.query<{ id: number }>(
      'SELECT id FROM users WHERE email = $1',
      [email],
    );
    expect(rows).toHaveLength(1);
  });

  it.each([undefined, 'Bearer invalid'])(
    'protects me without a valid token (header: %s)',
    async (header) => {
      const attempt = request(url).get('/auth/me');
      if (header !== undefined) attempt.set('Authorization', header);
      await attempt.expect(401);
    },
  );

  it('rejects privileged registration fields before inserting a user', async () => {
    const email = newEmail();
    await request(url)
      .post('/users')
      .send({ email, password, role: 'ADMIN' })
      .expect(400);
    const { rows } = await database.query<{ id: number }>(
      'SELECT id FROM users WHERE email = $1',
      [email],
    );
    expect(rows).toHaveLength(0);
  });
});
