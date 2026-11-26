CREATE TABLE "account_deletion" (
	"sub" text PRIMARY KEY NOT NULL,
	"requested_at" timestamp with time zone DEFAULT now() NOT NULL,
	"delete_after" timestamp with time zone NOT NULL,
	"cancel_token_hash" text NOT NULL
);
