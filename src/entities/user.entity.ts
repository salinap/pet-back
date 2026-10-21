import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
} from 'typeorm';
import { UserRole } from '../users/user-role.enum';

@Entity('users') // Название таблицы в базе данных
export class User {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column({ unique: true })
  email!: string;

  @Column({ type: 'enum', enum: UserRole, default: UserRole.USER })
  role!: UserRole;

  @Column({ type: 'varchar', length: 255, select: false })
  passwordHash!: string;

  @Column({ default: false })
  isEmailVerified!: boolean;

  @CreateDateColumn()
  createdAt!: Date;
}
