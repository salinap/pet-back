import { Transform } from 'class-transformer';
import { IsString, MinLength, MaxLength } from 'class-validator';

export class UpdateProfileDto {
  @IsString({ message: 'Имя должно быть строкой' })
  @Transform(({ value = '' }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  @MinLength(1, { message: 'Имя не может быть пустым' })
  @MaxLength(80, { message: 'Имя не должно превышать 80 символов' })
  displayName!: string;
}
