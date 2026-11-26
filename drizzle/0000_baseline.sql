CREATE TABLE "audit_log" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"at" timestamp with time zone DEFAULT now() NOT NULL,
	"actor_sub" text,
	"action" text NOT NULL,
	"target" text NOT NULL,
	"detail" jsonb
);
--> statement-breakpoint
CREATE TABLE "event_delivery" (
	"event_id" text NOT NULL,
	"subscriber_id" text NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"next_at" timestamp with time zone DEFAULT now() NOT NULL,
	"delivered_at" timestamp with time zone,
	"last_error" text,
	CONSTRAINT "event_delivery_pkey" PRIMARY KEY("event_id","subscriber_id")
);
--> statement-breakpoint
CREATE TABLE "event_outbox" (
	"id" text PRIMARY KEY NOT NULL,
	"type" text NOT NULL,
	"data" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "webhook_subscriber" (
	"id" text PRIMARY KEY DEFAULT gen_random_uuid()::text NOT NULL,
	"name" text NOT NULL,
	"url" text NOT NULL,
	"secret" text NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "webhook_subscriber_name_key" UNIQUE("name")
);
--> statement-breakpoint
ALTER TABLE "event_delivery" ADD CONSTRAINT "event_delivery_event_id_fkey" FOREIGN KEY ("event_id") REFERENCES "public"."event_outbox"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "event_delivery" ADD CONSTRAINT "event_delivery_subscriber_id_fkey" FOREIGN KEY ("subscriber_id") REFERENCES "public"."webhook_subscriber"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "event_delivery_due" ON "event_delivery" USING btree ("next_at") WHERE "event_delivery"."delivered_at" IS NULL;