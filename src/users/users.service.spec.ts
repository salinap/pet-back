import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../entities/user.entity';
import { HashService } from '../common/hash/hash.service';
import { UsersService } from './users.service';

describe('UsersService', () => {
  let service: UsersService;
  let repository: {
    find: jest.Mock;
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
      repository.save.mockResolvedValue({});

      await service.create('user@example.com', 'secret123');

      expect(repository.create).toHaveBeenCalledWith({
        email: 'user@example.com',
        passwordHash: 'hashed-value',
      });
      expect(repository.create.mock.calls[0][0]).not.toHaveProperty('password');
      expect(repository.save).toHaveBeenCalled();
    });
  });
});
