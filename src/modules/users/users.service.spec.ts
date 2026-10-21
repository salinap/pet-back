import { ConflictException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../../entities/user.entity';
import { UserRole } from './user-role.enum';
import { HashService } from '../hash/hash.service';
import { UsersService } from './users.service';

describe('UsersService', () => {
  let service: UsersService;
  let repository: {
    find: jest.Mock;
    findOne: jest.Mock;
    findOneBy: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
  };
  let hashService: { hash: jest.Mock };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: getRepositoryToken(User),
          useValue: {
            find: jest.fn(),
            findOne: jest.fn(),
            findOneBy: jest.fn(),
            create: jest.fn(),
            save: jest.fn(),
          },
        },
        {
          provide: HashService,
          useValue: { hash: jest.fn() },
        },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
    repository = module.get(getRepositoryToken(User));
    hashService = module.get(HashService);
    repository.findOne.mockResolvedValue(null);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should hash the password before saving the user', async () => {
      hashService.hash.mockResolvedValue('hashed-value');
      repository.create.mockReturnValue({});
      repository.save.mockResolvedValue({});

      await service.create('user@example.com', 'secret123');

      expect(hashService.hash).toHaveBeenCalledWith('secret123');
    });

    it('should save only the hash, never the plain password', async () => {
      hashService.hash.mockResolvedValue('hashed-value');
      repository.create.mockReturnValue({});
      repository.save.mockResolvedValue({
        id: 1,
        email: 'user@example.com',
        role: UserRole.USER,
        isEmailVerified: false,
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        passwordHash: 'hashed-value',
      });

      const result = await service.create('user@example.com', 'secret123');

      expect(repository.create).toHaveBeenCalledWith({
        email: 'user@example.com',
        passwordHash: 'hashed-value',
      });
      expect(repository.save).toHaveBeenCalled();
      expect(result).toEqual({
        id: 1,
        email: 'user@example.com',
        role: UserRole.USER,
        isEmailVerified: false,
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
      });
      expect(result).not.toHaveProperty('passwordHash');
    });

    it('should throw ConflictException if the email is already taken', async () => {
      repository.findOne.mockResolvedValue({ id: 1, email: 'user@example.com' });

      await expect(
        service.create('user@example.com', 'secret123'),
      ).rejects.toThrow(ConflictException);
      expect(hashService.hash).not.toHaveBeenCalled();
      expect(repository.save).not.toHaveBeenCalled();
    });
  });
});
