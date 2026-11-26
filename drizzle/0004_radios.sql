CREATE TABLE "user_radio" (
	"id" text PRIMARY KEY DEFAULT gen_random_uuid()::text NOT NULL,
	"sub" text NOT NULL,
	"model" text NOT NULL,
	"hamlib_model" integer,
	"label" text NOT NULL,
	"is_primary" boolean DEFAULT false NOT NULL,
	"sort_order" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "user_radio_sub" ON "user_radio" USING btree ("sub","sort_order");