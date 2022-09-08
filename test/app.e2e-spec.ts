import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { PrismaService } from '../src/prisma/prisma.service';
import { AppModule } from '../src/app.module';
import * as request from 'supertest';
import { LoginDto, SignupDto } from 'src/auth/dto';
import * as argon from 'argon2';
import { AuthService } from '../src/auth/auth.service';

describe('App e2e', () => {
  let app: INestApplication;
  let db: PrismaService;
  let auth: AuthService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = moduleRef.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
      }),
    );
    await app.init();

    db = app.get(PrismaService);
    auth = app.get(AuthService);
    await db.cleanDb();
  });

  beforeEach(async () => {
    await db.cleanDb();
  });

  afterAll(() => {
    app.close();
  });

  describe('Auth', () => {
    describe('/signup', () => {
      it.each([
        [[{ email: 'test@test.com', password: '123' }], [201]],
        [[{}], [400]],
        [[{ email: 'test', password: '123' }], [201]],
        [
          [
            { email: 'test@test.com', password: '123' },
            { email: 'test1@test.com', password: '123' },
          ],
          [201, 201],
        ],
        [
          [
            { email: 'test@test.com', password: '123' },
            { email: 'test@test.com', password: '123' },
          ],
          [201, 403],
        ],
      ])(
        'When %j should return %s',
        (dtos: SignupDto[], expectedStatuses: number[]) => {
          dtos.forEach((dto, index) => {
            request(app.getHttpServer())
              .post('/auth/signup')
              .send(dto)
              .expect(expectedStatuses[index]);
          });
        },
      );
    });

    describe('/login', () => {
      it.each([
        [{ email: 'test@test.com', password: '123' }, 200],
        [{ email: 'test1@test.com', password: '123' }, 403],
        [{ email: 'test@test.com', password: '1233' }, 403],
      ])(
        'When %j should return %s',
        async (dto: LoginDto, expectedStatus: number) => {
          await db.user.create({
            data: {
              email: 'test@test.com',
              hash: await argon.hash('123'),
            },
          });
          return request(app.getHttpServer())
            .post('/auth/login')
            .send(dto)
            .expect(expectedStatus)
            .expect((res: request.Response) => {
              if (expectedStatus === 200) {
                expect(res.body).toHaveProperty('accessToken');
              } else {
                expect(res.body).not.toHaveProperty('accessToken');
              }
            });
        },
      );
    });
  });

  describe('User', () => {
    describe('/me', () => {
      it('When not authorized should return 401', () => {
        return request(app.getHttpServer()).get('/user/me').expect(401);
      });

      it('When authorized should return 200', async () => {
        const email = 'test@test.com';
        const user = await db.user.create({
          data: {
            email,
            hash: await argon.hash('123'),
          },
        });
        const token = await auth.signToken(user);
        return request(app.getHttpServer())
          .get('/user/me')
          .set('Authorization', `Bearer ${token}`)
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('email', email);
            expect(res.body).not.toHaveProperty('hash');
          });
      });
    });
  });
});
