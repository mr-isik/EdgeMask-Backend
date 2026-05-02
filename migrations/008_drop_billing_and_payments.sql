-- Drop Dodo Payments webhook events table
DROP TABLE IF EXISTS dodo_webhook_events;

-- Drop Dodo customer mapping from users table
ALTER TABLE public.users
DROP COLUMN IF EXISTS dodo_customer_id;
