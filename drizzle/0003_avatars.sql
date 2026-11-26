ALTER TABLE "profile" ADD COLUMN "avatar_source" text DEFAULT 'none' NOT NULL;--> statement-breakpoint
ALTER TABLE "profile" ADD COLUMN "avatar_url" text;