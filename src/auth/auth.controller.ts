import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { AuthService } from './auth.service';
import Tokens from './interfaces/tokens.interface';
import { Request } from 'express';
import { AccessTokenGuard } from 'src/common/guards/accessToken.guard';
import { RefreshTokenGuard } from 'src/common/guards/refreshToken.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  signUp(@Body() authCredentialsDto: AuthCredentialsDto): Promise<Tokens> {
    return this.authService.signUp(authCredentialsDto);
  }

  @Post('signin')
  @HttpCode(HttpStatus.OK)
  signIn(@Body() authCredentialsDto: AuthCredentialsDto): Promise<Tokens> {
    return this.authService.signIn(authCredentialsDto);
  }

  @UseGuards(AccessTokenGuard)
  @Post('signout')
  @HttpCode(HttpStatus.OK)
  signOut(@Req() req: Request): Promise<void> {
    const user = req.user;
    return this.authService.signOut(user['email']);
  }

  @UseGuards(RefreshTokenGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(@Req() req: Request): Promise<Tokens> {
    const email = req.user['email'];
    const refreshToken = req.user['refreshToken'];
    return this.authService.refreshTokens(email, refreshToken);
  }
}
