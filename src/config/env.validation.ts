import {
  IsInt,
  IsNotEmpty,
  IsString,
  Matches,
  Max,
  Min,
} from 'class-validator';
import { plainToInstance, Type } from 'class-transformer';
import { validateSync } from 'class-validator';

export class EnvironmentVariables {
  @IsString()
  @IsNotEmpty()
  @Matches(/\S/)
  DB_USER!: string;

  @IsString()
  @IsNotEmpty()
  DB_PASSWORD!: string;

  @IsString()
  @IsNotEmpty()
  @Matches(/\S/)
  DB_NAME!: string;

  @IsString()
  @IsNotEmpty()
  @Matches(/\S/)
  DB_HOST!: string;

  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(65535)
  DB_PORT: number = 5433;

  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(65535)
  PORT: number = 4000;

  @IsString()
  @IsNotEmpty()
  @Matches(/^[a-fA-F0-9]{64}$/)
  JWT_SECRET!: string;

  @IsString()
  @IsNotEmpty()
  @Matches(/\S/)
  JWT_ISSUER!: string;

  @IsString()
  @IsNotEmpty()
  @Matches(/\S/)
  JWT_AUDIENCE!: string;

  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(900)
  JWT_ACCESS_TTL_SECONDS!: number;
}

export function validate(
  config: Record<string, unknown>,
): EnvironmentVariables {
  const validatedConfig = plainToInstance(EnvironmentVariables, config);

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,
    validationError: {
      target: false,
      value: false,
    },
  });

  if (errors.length > 0) {
    const fields = errors.map((error) => error.property).join(', ');

    throw new Error(`Некорректная конфигурация: ${fields}`);
  }

  return validatedConfig;
}
