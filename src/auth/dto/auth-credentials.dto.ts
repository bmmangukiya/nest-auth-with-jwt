import { IsString, Matches, MaxLength, MinLength } from 'class-validator';

export class AuthCredentialsDto {
  @IsString()
  @MinLength(4)
  @MaxLength(20)
  email: string;

  @IsString()
  @MinLength(8)
  @MaxLength(32)
  @Matches(
    /^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#$%^&*()_+{}\|:;<>,.?/~[\]^$])[^\s.]+$/,
    {
      message: 'password is too weak',
    }
  )
  password: string;
}
