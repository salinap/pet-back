import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../../entities/user.entity';
import type { UserResponse } from '../../entities/user.entity';
import { QueryFailedError, Repository } from 'typeorm';
import { HashService } from '../hash/hash.service';
import { UserRole } from './user-role.enum';
import { toUserResponse } from './user.mapper';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
    private readonly hashService: HashService,
  ) { }

  async findAll(): Promise<UserResponse[]> {
    const users = await this.usersRepository.find();
    return users.map(toUserResponse);
  }

  async findById(id: number): Promise<UserResponse | null> {
    const user = await this.usersRepository.findOneBy({ id });
    return user === null ? null : toUserResponse(user);
  }

  async getProfileFor(
    targetUserId: number,
    requesterId: number,
  ): Promise<UserResponse> {
    const requester = await this.findById(requesterId);

    if (requester === null) {
      throw new UnauthorizedException();
    }

    if (requester.role !== UserRole.ADMIN && requester.id !== targetUserId) {
      throw new NotFoundException('User not found');
    }

    const targetUser = await this.findById(targetUserId);

    if (targetUser === null) {
      throw new NotFoundException('User not found');
    }

    return toUserResponse(targetUser);
  }

  async updateProfileFor(
    targetUserId: number,
    requesterId: number,
    displayName: string,
  ): Promise<UserResponse> {
    const requester = await this.findById(requesterId);
    if (requester === null) {
      throw new UnauthorizedException();
    }
    if (requester.id !== targetUserId) {
      throw new NotFoundException('User not found');
    }
    const result = await this.usersRepository.update(
      { id: targetUserId },
      { displayName },
    );

    if (result.affected !== 1) {
      throw new NotFoundException('User not found');
    }

    const targetUser = await this.findById(targetUserId);

    if (targetUser === null) {
      throw new NotFoundException('User not found');
    }

    return targetUser;
  }

  async findCredentialsByEmail(email: string): Promise<User | null> {
    const user = await this.usersRepository.findOne({
      select: {
        id: true,
        email: true,
        passwordHash: true,
        role: true,
        isEmailVerified: true,
        createdAt: true,
      },
      where: { email },
    });

    return user;
  }

  async create(email: string, password: string): Promise<UserResponse> {
    const existingUser = await this.usersRepository.findOne({
      where: { email },
    });

    if (existingUser) {
      throw new ConflictException('Email already exists');
    }
    const passwordHash = await this.hashService.hash(password);
    const user = this.usersRepository.create({ email, passwordHash });
    let result: User;
    try {
      result = await this.usersRepository.save(user);
    } catch (error) {
      if (this.isUniqueViolation(error)) {
        throw new ConflictException('Email already exists');
      }
      throw error;
    }
    return toUserResponse(result);
  }

  private isUniqueViolation(error: unknown): boolean {
    return (
      error instanceof QueryFailedError &&
      (error.driverError as { code?: string }).code === '23505'
    );
  }
}
