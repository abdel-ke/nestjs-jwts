import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { AtGuard } from './common/guards/At,guard';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe());
  // app.useGlobalGuards(new AtGuard());
  await app.listen(3000);
}
bootstrap();
