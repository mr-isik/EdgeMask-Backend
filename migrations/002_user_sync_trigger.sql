-- 002_user_sync_trigger.sql
-- Creates a secure database function and trigger to sink Supabase Auth users to public.users
-- This ensures the foreign key constraints in api_keys and usage_logs always pass.

-- 1. Create the sync function
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.users (id, email, plan)
  VALUES (new.id, new.email, 'growth')
  ON CONFLICT (id) DO NOTHING;
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- 2. Create the trigger on auth.users
DO $$
BEGIN
  -- Drop the trigger if it already exists to avoid duplicates
  DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
  
  CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();
EXCEPTION
  -- If auth.users doesn't exist (e.g. non-Supabase local test), safely ignore
  WHEN undefined_table THEN
    NULL;
END $$;

-- 3. Sync any existing users that might have slipped through
DO $$
BEGIN
  IF EXISTS (
      SELECT 1 FROM information_schema.tables WHERE table_schema = 'auth' AND table_name = 'users'
  ) THEN
      INSERT INTO public.users (id, email, plan)
      SELECT id, email, 'growth' FROM auth.users
      ON CONFLICT (id) DO NOTHING;
  END IF;
END $$;
