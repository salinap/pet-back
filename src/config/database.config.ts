import { join } from 'node:path';
import type { DataSourceOptions } from 'typeorm';
import { User } from '../entities/user.entity';
import type { DatabaseEnvironmentVariables } from './env.validation';

export function createDatabaseOptions(
  config: DatabaseEnvironmentVariables,
): DataSourceOptions {
  return {
    type: 'postgres',
    host: config.DB_HOST,
    port: config.DB_PORT,
    username: config.DB_USER,
    password: config.DB_PASSWORD,
    database: config.DB_NAME,
    entities: [User],
    migrations: [join(__dirname, '../database/migrations/*{.ts,.js}')],
    synchronize: false,
  };
}
