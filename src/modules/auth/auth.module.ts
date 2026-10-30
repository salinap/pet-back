import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { HashService } from '../hash/hash.service';

@Module({
  imports: [UsersModule],
  controllers: [AuthController],
  providers: [AuthService, HashService],
})
export class AuthModule {}
