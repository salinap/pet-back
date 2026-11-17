import { MigrationInterface, QueryRunner } from "typeorm";

export class CreateAuthSessions1794912114535 implements MigrationInterface {
    name = 'CreateAuthSessions1794912114535'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "auth_sessions" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "userId" integer NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "expiresAt" TIMESTAMP WITH TIME ZONE NOT NULL, "revokedAt" TIMESTAMP WITH TIME ZONE, CONSTRAINT "PK_641507381f32580e8479efc36cd" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_auth_sessions_userId" ON "auth_sessions"  ("userId") `);
        await queryRunner.query(`ALTER TABLE "auth_sessions" ADD CONSTRAINT "FK_925b24d7fc2f9324ce972aee025" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "auth_sessions" DROP CONSTRAINT "FK_925b24d7fc2f9324ce972aee025"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_auth_sessions_userId"`);
        await queryRunner.query(`DROP TABLE "auth_sessions"`);
    }

}
