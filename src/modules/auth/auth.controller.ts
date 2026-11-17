import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { ThrottlerGuard } from '@nestjs/throttler';
import type { AuthenticatedRequest } from './types/authenticated-request';
import { Public } from './decorators/public.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  logout(@Req() request: AuthenticatedRequest) {
    return this.authService.logout(request.user.userId, request.user.sessionId);
  }

  @Post('login')
  @Public()
  @HttpCode(HttpStatus.OK)
  @UseGuards(ThrottlerGuard)
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto.email, dto.password);
  }

  @Get('me')
  me(@Req() request: AuthenticatedRequest) {
    return this.authService.getProfile(request.user.userId);
  }
}
