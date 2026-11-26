CREATE TABLE "api_key" (
	"jti" text PRIMARY KEY NOT NULL,
	"sub" text NOT NULL,
	"aud" text NOT NULL,
	"scopes" text[] NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"days" integer NOT NULL,
	"renewable" boolean DEFAULT false NOT NULL,
	"client_id" text,
	"replaces" text,
	"replaced_by" text,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revoke_reason" text,
	"reminded_days" integer
);
--> statement-breakpoint
ALTER TABLE "webhook_subscriber" ADD COLUMN "audience" text;--> statement-breakpoint
CREATE INDEX "api_key_sub" ON "api_key" USING btree ("sub");--> statement-breakpoint
CREATE INDEX "api_key_revoked" ON "api_key" USING btree ("aud","revoked_at") WHERE "api_key"."revoked_at" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "api_key_expiring" ON "api_key" USING btree ("expires_at") WHERE "api_key"."revoked_at" IS NULL;