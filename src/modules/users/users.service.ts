import { ConflictException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../../entities/user.entity';
import type { UserResponse } from '../../entities/user.entity';
import { QueryFailedError, Repository } from 'typeorm';
import { HashService } from '../hash/hash.service';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
    private readonly hashService: HashService,
  ) {}

  async findAll(): Promise<UserResponse[]> {
    return this.usersRepository.find();
  }

  async findById(id: number): Promise<UserResponse | null> {
    return this.usersRepository.findOneBy({ id });
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
    return {
      id: result.id,
      email: result.email,
      role: result.role,
      isEmailVerified: result.isEmailVerified,
      createdAt: result.createdAt,
    };
  }

  private isUniqueViolation(error: unknown): boolean {
    return (
      error instanceof QueryFailedError &&
      (error.driverError as { code?: string }).code === '23505'
    );
  }
}
