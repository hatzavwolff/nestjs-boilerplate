import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddPolicyToUser1761223578126 implements MigrationInterface {
  name = 'AddPolicyToUser1761223578126';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "user" ADD "policy" boolean NOT NULL DEFAULT false`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "policy"`);
  }
}
