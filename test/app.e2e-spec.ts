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
    };
    expect(profile).toEqual({
      id: expect.any(Number) as unknown,
      email,
      role: 'USER',
      isEmailVerified: false,
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
