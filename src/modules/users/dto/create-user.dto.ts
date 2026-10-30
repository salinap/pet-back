import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsString,
  MinLength,
  MaxLength,
  IsNotEmpty,
  IsByteLength,
} from 'class-validator';

export class CreateUserDto {
  @IsEmail({}, { message: 'Некорректный формат email' })
  @IsNotEmpty({ message: 'Email не может быть пустым' })
  @MaxLength(255, { message: 'Email не должен превышать 255 символов' })
  @Transform(({ value = '' }: { value: string }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value,
  )
  email!: string;

  @IsString({ message: 'Пароль должен быть строкой' })
  @IsNotEmpty({ message: 'Пароль обязателен' })
  @MinLength(8, { message: 'Пароль должен быть не менее 8 символов' })
  @IsByteLength(0, 72, {
    message: 'Пароль не должен превышать 72 байта UTF-8',
  })
  password!: string;
}
