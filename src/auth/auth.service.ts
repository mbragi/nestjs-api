import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  login() {
    return 'This action returns all cats';
  }
  async signUp(dto: AuthDto) {
    //generate the password hash
    const hash = await argon.hash(dto.password);
    //create the user
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        hashedPassword: hash,
      },
    });
    delete user.hashedPassword;
    //return the user
    return user;
    return 'This action adds a new cat';
  }
}
