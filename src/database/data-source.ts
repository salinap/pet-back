import 'reflect-metadata';
import { loadEnvFile } from 'node:process';
import { DataSource } from 'typeorm';
import { createDatabaseOptions } from '../config/database.config';
import { validateDatabase } from '../config/env.validation';

try {
  loadEnvFile('.env');
} catch (error) {
  if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
    throw error;
  }
}

const config = validateDatabase(process.env);

export default new DataSource(createDatabaseOptions(config));
