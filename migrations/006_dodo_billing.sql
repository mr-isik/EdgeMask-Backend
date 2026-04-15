-- Add Dodo Payments customer mapping to users for usage billing.
ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS dodo_customer_id TEXT;

CREATE INDEX IF NOT EXISTS idx_users_dodo_customer_id
ON public.users(dodo_customer_id)
WHERE dodo_customer_id IS NOT NULL;
