import { Body, Controller, HttpCode, HttpStatus, Post, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Token } from './types';

@Controller('auth')
export class AuthController {
    constructor(private authservice: AuthService) {}
  @Post('/local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() dto: AuthDto): Promise<Token> {
    return this.authservice.signupLocal(dto);
  }

  @Post('/local/signin')
  @HttpCode(HttpStatus.OK)
  signinLocal(@Body() dto: AuthDto): Promise<Token> {
    return this.authservice.signinLocal(dto)
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request): Promise<Token> {
    // return ;
    const userId = req.user;
    console.log("req.user: ", req.user)
    return this.authservice.logout(userId['sub']);
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('/refresh')
  @HttpCode(HttpStatus.OK)
  refreshToken(@Req() req: Request): Promise<Token> {
    const user = req.user; 
    console.log(user);
    return this.authservice.refreshToken(user['sub'], user['refreshToken']);
  }
}
