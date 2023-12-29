import {
  ConflictException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { IsNull, Not, Repository } from 'typeorm';
import { User } from './user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

import * as bcrypt from 'bcrypt';
import Tokens from './interfaces/tokens.interface';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService
  ) {}

  async signUp(authCredentialsDto: AuthCredentialsDto): Promise<Tokens> {
    const { email, password } = authCredentialsDto;

    if (!email || !password) {
      throw new BadRequestException('Invalid credentials provided');
    }

    const user = this.usersRepository.create({
      email,
      password: await this.hashData(password),
    });

    try {
      const tokens = await this.getTokens({ email });
      user.refreshToken = await this.hashData(tokens.refreshToken);
      await this.usersRepository.save(user);
      return tokens;
    } catch (error) {
      console.error('Error during signUp:', error);

      if (error.code === '23505') {
        throw new ConflictException('Username already exists');
      } else {
        throw new InternalServerErrorException();
      }
    }
  }

  async signIn(authCredentialsDto: AuthCredentialsDto): Promise<Tokens> {
    const { email, password } = authCredentialsDto;
    const user = await this.usersRepository.findOneBy({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      const tokens = await this.getTokens({ email });
      await this.updateRefreshToken(user, tokens.refreshToken);

      return tokens;
    } else {
      throw new UnauthorizedException('Invalid credentials');
    }
  }

  async signOut(email: string) {
    await this.usersRepository.update(
      { email, refreshToken: Not(IsNull()) },
      { refreshToken: null }
    );
  }

  async refreshTokens(email: string, refreshToken: string): Promise<Tokens> {
    const user = await this.usersRepository.findOneBy({ email });

    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Access Denied');
    }

    const refreshTokenMatches = await bcrypt.compare(
      refreshToken,
      user.refreshToken
    );

    if (!refreshTokenMatches) {
      throw new ForbiddenException('Access Denied');
    }

    const tokens = await this.getTokens({ email });
    await this.updateRefreshToken(user, tokens.refreshToken);
    return tokens;
  }

  async getTokens(user: JwtPayload): Promise<Tokens> {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(user, {
        secret: this.configService.get('JWT_ACCESS_SECRET'),
        expiresIn: this.configService.get('ACCESS_TOKEN_EXPIRATION_TIME'),
      }),
      this.jwtService.signAsync(user, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get('REFRESH_TOKEN_EXPIRATION_TIME'),
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async updateRefreshToken(user: User, newRefreshToken: string) {
    const hashedRefreshToken = await this.hashData(newRefreshToken);
    await this.usersRepository.save({
      ...user,
      refreshToken: hashedRefreshToken,
    });
  }

  async hashData(data: string): Promise<string> {
    const salt = await bcrypt.genSalt();
    return bcrypt.hash(data, salt);
  }
}
