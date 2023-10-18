import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt'
import { User } from './models/users.model';
import { Model } from 'mongoose';
import { AuthService } from 'src/auth/auth.service';
import { SignupDto } from './dto/singup.dto';
import { SigninDto } from './dto/singin.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel('User')
    private readonly usersModel: Model<User>,
    private readonly authService: AuthService
  ){}

  public async signup(signupDto: SignupDto): Promise<User> {
    const user = new this.usersModel(signupDto)
    return user.save()
  }

  public async signin(
    signinDto: SigninDto
  ):Promise<{ name: string; jwtToken: string; email: string }> {
    const user = await this.findByEmail(signinDto.email)
    const match = await this.checkPassword(signinDto.password, user)

    if(!match){
      throw new NotFoundException('Invalid credentials')
    }

    const jwtToken = await this.authService.createAcessToken(user._id)
    return { name: user.name, jwtToken: jwtToken, email: user.email }
  }

  private async findByEmail(email: string): Promise<User> {
    const user = await this.usersModel.findOne({ email })
    if (!user) {
      throw new NotFoundException('Email not found')
    }
    return user
  }

  private async checkPassword(password: string, user: User): Promise<boolean> {
    const isMatched = await bcrypt.compare(password, user.password)
    if(!isMatched){
      throw new NotFoundException('Password not found')
    }
    return isMatched
  }


}
