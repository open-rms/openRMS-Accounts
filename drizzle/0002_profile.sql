CREATE TABLE "profile" (
	"sub" text PRIMARY KEY NOT NULL,
	"bio" text,
	"city" text,
	"links" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"visibility" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"hidden" boolean DEFAULT false NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
