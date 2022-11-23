import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt'
import { Token } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService,
    private jwtService: JwtService) { }

  async signupLocal(dto: AuthDto): Promise<Token> {
    const findOne = this.prisma.user.findUnique({
      where: {
        email: dto.email
      }
    });
    if (findOne) throw new HttpException('this email already exist!!', HttpStatus.FOUND);
    const hash = await this.hashData(dto.password);
    const newUser = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash
      },
    });
    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRtHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async signinLocal(dto: AuthDto): Promise<Token> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email
      }
    })
    if (!user) throw new HttpException(`this email not exist`, HttpStatus.NOT_FOUND);
    const checkPass = await bcrypt.compare(dto.password, user.hash);
    if (!checkPass) throw new HttpException(`password incorrect`, HttpStatus.NOT_FOUND);
    const tokens = await this.getTokens(user.id, dto.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async logout(userId: number): Promise<Token> {
    const user = await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null
        }
      },
      data: {
        hashedRt: null
      }
    })
    console.log("update: ", user);
    return ;
  }

  async refreshToken(userId: number, rt: string) {
    const findOne = await this.prisma.user.findUnique({
      where: {
        id: userId
      }
    })
    if (!findOne) throw new HttpException('user Not found!!', HttpStatus.NOT_FOUND);
    const rtCompare = await bcrypt.compare(rt, findOne.hashedRt);
    if (!rtCompare) throw new HttpException('access denied!!', HttpStatus.NOT_FOUND);
    const token = await this.getTokens(userId, findOne.email);
    await this.updateRtHash(userId, token.refresh_token);
    return token;
  }

  async updateRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      }
    })
  }

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  async getTokens(userId: number, email: string): Promise<Token> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'at-secret',
          expiresIn: 60 * 15,
        }),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'rt-secret',
          expiresIn: 60 * 60 * 24 * 7,
        })
    ]);
    return ({
      access_token: at,
      refresh_token: rt,
    })
  }
}