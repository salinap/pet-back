import type { User, UserResponse } from '../../entities/user.entity';

type UserResponseSource = Pick<
  User,
  'id' | 'email' | 'role' | 'isEmailVerified' | 'createdAt' | 'displayName'
>;

export function toUserResponse(user: UserResponseSource): UserResponse {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    isEmailVerified: user.isEmailVerified,
    createdAt: user.createdAt,
    displayName: user.displayName,
  };
}
