import { Transform } from 'class-transformer';
import {
  IsByteLength,
  IsEmail,
  IsNotEmpty,
  IsString,
  MaxLength,
} from 'class-validator';

export class LoginDto {
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value,
  )
  @IsEmail({}, { message: 'Некорректный формат email' })
  @MaxLength(255, { message: 'Email не должен превышать 255 символов' })
  email!: string;

  @IsString({ message: 'Пароль должен быть строкой' })
  @IsNotEmpty({ message: 'Пароль обязателен' })
  @IsByteLength(0, 72, {
    message: 'Пароль не должен превышать 72 байта UTF-8',
  })
  password!: string;
}
