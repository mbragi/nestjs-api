import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService
  ) {}
  async login(dto: AuthDto) {
    //TODO: implement login
    //Find the user by email
    const user =
      await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });
    //if user not found throw error
    if (!user) {
      throw new ForbiddenException(
        "User doesn't exist"
      );
    }
    //compare the password hash
    const isPasswordValid = await argon.verify(
      user.hashedPassword,
      dto.password
    );
    //if password is incorrect throw error
    if (!isPasswordValid) {
      throw new ForbiddenException(
        'Incorrect password'
      );
    }
    //generate the jwt token

    //return the user and token
    return this.signToken(user.id, user.email);
  }
  async signUp(dto: AuthDto) {
    //generate the password hash
    const hash = await argon.hash(dto.password);

    try {
      //create the user
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hashedPassword: hash,
        },
      });
      //return the user
      console.log('user', user);

      return this.signToken(user.id, user.email);
    } catch (error) {
      if (
        error instanceof
        PrismaClientKnownRequestError
      ) {
        if (error.code === 'P2002') {
          throw new ForbiddenException(
            'Email already exists'
          );
        }
      }
    }
  }

  async signToken(
    userId: number,
    email: string
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');
    const token = await this.jwt.signAsync(
      payload,
      {
        expiresIn: '15m',
        secret: secret,
      }
    );

    return {
      access_token: token,
    };
  }
}
