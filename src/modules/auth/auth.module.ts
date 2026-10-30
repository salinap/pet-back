import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { HashService } from '../hash/hash.service';
import { ThrottlerModule } from '@nestjs/throttler';

@Module({
  imports: [
    UsersModule,
    ThrottlerModule.forRoot([
      {
        ttl: 60_000,
        limit: 5,
        blockDuration: 60_000,
      },
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, HashService],
})
export class AuthModule {}
