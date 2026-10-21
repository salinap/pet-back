import { Test, TestingModule } from '@nestjs/testing';
import { HashService } from './hash.service';

describe('HashService', () => {
  let service: HashService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [HashService],
    }).compile();

    service = module.get<HashService>(HashService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should hash the password without storing it as plain text', async () => {
    const hash = await service.hash('secret123');

    expect(hash).not.toBe('secret123');
    expect(hash).toMatch(/^\$2[aby]\$/);
  });

  it('should produce different hashes for the same password', async () => {
    const first = await service.hash('secret123');
    const second = await service.hash('secret123');

    expect(first).not.toBe(second);
  });

  it('should confirm a matching password', async () => {
    const hash = await service.hash('secret123');

    await expect(service.compare('secret123', hash)).resolves.toBe(true);
  });

  it('should reject a wrong password', async () => {
    const hash = await service.hash('secret123');

    await expect(service.compare('wrong-password', hash)).resolves.toBe(false);
  });
});
