import 'dotenv/config';
import {
  ClassSerializerInterceptor,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory, Reflector } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { useContainer } from 'class-validator';
import helmet from 'helmet';
import { DataSource } from 'typeorm';
import { AppModule } from './app.module';
import validationOptions from './utils/validation-options';
import { AllConfigType } from './config/config.type';
import { ResolvePromisesInterceptor } from './utils/serializer.interceptor';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log'],
  });
  useContainer(app.select(AppModule), { fallbackOnErrors: true });
  const configService = app.get(ConfigService<AllConfigType>);

  // Check database connection
  try {
    const dataSource = app.get(DataSource);
    if (dataSource.isInitialized) {
      const dbConfig = configService.get('database', { infer: true });
      logger.log(
        `✅ Successfully connected to PostgreSQL database: ${dbConfig?.host}:${dbConfig?.port}/${dbConfig?.name}`,
      );
    } else {
      logger.warn('⚠️  Database connection not initialized');
    }
  } catch (error) {
    logger.error('❌ Failed to connect to PostgreSQL database', error);
  }

  // Security: Enable Helmet for security headers
  app.use(helmet());

  // Security: Configure CORS properly
  const frontendDomain = configService.get('app.frontendDomain', {
    infer: true,
  });
  app.enableCors({
    origin: frontendDomain || true,
    credentials: true,
  });

  app.enableShutdownHooks();
  app.setGlobalPrefix(
    configService.getOrThrow('app.apiPrefix', { infer: true }),
    {
      exclude: ['/'],
    },
  );
  // Versioning disabled - endpoints will be /api/auth/... instead of /api/v1/auth/...
  // app.enableVersioning({
  //   type: VersioningType.URI,
  // });
  app.useGlobalPipes(new ValidationPipe(validationOptions));
  app.useGlobalInterceptors(
    // ResolvePromisesInterceptor is used to resolve promises in responses because class-transformer can't do it
    // https://github.com/typestack/class-transformer/issues/549
    new ResolvePromisesInterceptor(),
    new ClassSerializerInterceptor(app.get(Reflector)),
  );

  const options = new DocumentBuilder()
    .setTitle('API')
    .setDescription('API docs')
    .setVersion('1.0')
    .addBearerAuth()
    .addGlobalParameters({
      in: 'header',
      required: false,
      name: process.env.APP_HEADER_LANGUAGE || 'x-custom-lang',
      schema: {
        example: 'en',
      },
    })
    .build();

  const document = SwaggerModule.createDocument(app, options);
  SwaggerModule.setup('docs', app, document);

  const port = configService.getOrThrow('app.port', { infer: true });
  await app.listen(port);

  logger.log(`🚀 Application is running on: http://localhost:${port}`);
  logger.log(
    `📚 API Documentation available at: http://localhost:${port}/docs`,
  );
}
void bootstrap();
