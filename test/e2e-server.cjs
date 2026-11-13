// Run real compiled modules in Node, outside Jest's CommonJS loader.
const { NestFactory } = require('@nestjs/core');
const { Client } = require('pg');

const expected = {
  NODE_ENV: 'test',
  DB_HOST: '127.0.0.1',
  DB_PORT: '5434',
  DB_USER: 'pet_test',
  DB_PASSWORD: 'pet_test_password',
  DB_NAME: 'pet_test',
};
let app;
let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  await app?.close();
  process.exit(0);
}
process.on('SIGTERM', () => void stop());
process.on('disconnect', () => void stop());

async function start() {
  // Validate the test environment before importing configuration or running migrations.
  for (const [key, value] of Object.entries(expected)) {
    if (process.env[key] !== value) {
      throw new Error(`Unsafe e2e configuration: ${key}`);
    }
  }
  const client = new Client({
    host: expected.DB_HOST,
    port: Number(expected.DB_PORT),
    user: expected.DB_USER,
    password: expected.DB_PASSWORD,
    database: expected.DB_NAME,
    connectionTimeoutMillis: 3000,
  });
  try {
    await client.connect();
    const { rows } = await client.query(
      'SELECT current_database() AS database, current_user AS username',
    );
    if (rows[0].database !== 'pet_test' || rows[0].username !== 'pet_test') {
      throw new Error('Refusing to initialize a non-test database');
    }
  } finally {
    await client.end();
  }
  const dataSource = require('../dist/database/data-source.js').default;
  try {
    await dataSource.initialize();
    await dataSource.runMigrations();
  } finally {
    if (dataSource.isInitialized) {
      await dataSource.destroy();
    }
  }
  const { AppModule } = require('../dist/app.module.js');
  const { configureApp } = require('../dist/configure-app.js');
  app = await NestFactory.create(AppModule, { logger: false });
  configureApp(app);
  await app.listen(0, '127.0.0.1');
  process.send({ url: await app.getUrl() });
}
start().catch((error) => {
  console.error(error);
  process.exit(1);
});
