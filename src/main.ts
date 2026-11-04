import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module';
import { configureApp } from './configure-app';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  configureApp(app);

  const config = app.get(ConfigService);
  await app.listen(config.getOrThrow<number>('PORT'));
}

bootstrap().catch((error: unknown) => {
  console.error('Failed to start application', error);
  process.exitCode = 1;
});
