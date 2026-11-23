-- Medewerkers (alle docenten) mogen inloggen met e-mail + wachtwoord, zolang hun SSO-vinkje uit staat.
--   Beheerder maakt een tijdelijk wachtwoord (Klassen & gebruikers → Docenten); medewerker wijzigt het zelf.
--   SSO-vinkje aan -> wachtwoord werkt niet meer, alleen Microsoft. Beheerders: wachtwoord werkt altijd.
-- Vervangt de beheerders-beperking uit login-eisen.sql en beheer-wachtwoord.sql.

create or replace function public.my_email()
 returns text language sql stable security definer set search_path to 'public'
as $function$
  with t as (
    select lower(nullif(auth.jwt() ->> 'email', '')) e,
           auth.jwt() -> 'app_metadata' ->> 'provider' p,
           coalesce((auth.jwt() ->> 'is_anonymous')::boolean, false) anon)
  select coalesce(
    (select e from t where not anon and e is not null and (
       (p = 'azure' and not exists (select 1 from leerlingen l where lower(l.email) = t.e and not l.sso))
       or (p = 'email' and exists (select 1 from docenten d where lower(d.email) = t.e and (d.is_admin or not d.sso))))),
    (select lower(coalesce(l.email, d.email)) from code_sessies c
       left join leerlingen l on l.id = c.leerling_id and not l.sso
       left join docenten d on d.id = c.docent_id and not d.sso and not d.is_admin
      where c.uid = auth.uid() and c.aangemaakt > now() - interval '12 hours'),
    '')
$function$;

-- Nieuwe e-mailaccounts alleen voor adressen uit de docentenlijst
create or replace function public.blokkeer_aanmelden()
 returns trigger language plpgsql security definer set search_path to 'public'
as $function$
begin
  if coalesce(new.is_anonymous, false) then return new; end if;
  if coalesce(new.raw_app_meta_data ->> 'provider', 'email') <> 'email' then return new; end if;
  if exists (select 1 from docenten where lower(email) = lower(new.email)) then return new; end if;
  raise exception 'Aanmelden met e-mail is niet toegestaan';
end $function$;
revoke execute on function public.blokkeer_aanmelden() from public, anon, authenticated;

-- Wachtwoord instellen voor elke docent (niet alleen beheerders)
create or replace function beheer_zet_wachtwoord(p_email text, p_ww text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_email text := lower(trim(p_email));
  v_id uuid;
begin
  if coalesce((auth.jwt() ->> 'is_anonymous')::boolean, true) then
    raise exception 'Log in met je eigen beheerdersaccount.';
  end if;
  if not is_admin() then raise exception 'Alleen beheerders kunnen wachtwoorden instellen.'; end if;
  if not exists (select 1 from docenten where lower(email) = v_email) then
    raise exception 'Dit adres staat niet in de docentenlijst.';
  end if;
  if length(coalesce(p_ww, '')) < 10 then raise exception 'Kies een wachtwoord van minstens 10 tekens.'; end if;

  select id into v_id from auth.users where lower(email) = v_email;
  if v_id is null then
    v_id := gen_random_uuid();
    insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
      raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', v_id, 'authenticated', 'authenticated', v_email,
      crypt(p_ww, gen_salt('bf')), now(),
      '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');
    insert into auth.identities (id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
    values (gen_random_uuid(), v_id, v_id::text,
      jsonb_build_object('sub', v_id::text, 'email', v_email, 'email_verified', true), 'email', now(), now(), now());
  else
    update auth.users
       set encrypted_password = crypt(p_ww, gen_salt('bf')),
           email_confirmed_at = coalesce(email_confirmed_at, now()),
           updated_at = now()
     where id = v_id;
  end if;
end $$;
revoke all on function beheer_zet_wachtwoord(text, text) from public, anon;
grant execute on function beheer_zet_wachtwoord(text, text) to authenticated;

-- Tijdelijke wachtwoorden maken voor een groep docenten (beheerders overgeslagen, eigen account ook).
-- Het wachtwoord is daarna niet meer op te vragen (alleen de hash staat in de database).
create or replace function maak_tijdelijke_wachtwoorden(p_docenten uuid[])
returns table (docent_id uuid, naam text, email text, wachtwoord text)
language plpgsql security definer set search_path = public, extensions as $$
declare
  r record;
  v_ww text;
  tekens constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
begin
  if not is_admin() then raise exception 'Alleen beheerders kunnen wachtwoorden maken.'; end if;
  for r in select d.id, d.naam, lower(d.email) email from docenten d
            where d.id = any(p_docenten) and not d.is_admin and lower(d.email) <> my_email() order by d.naam loop
    select string_agg(substr(tekens, 1 + (get_byte(b, i) % length(tekens)), 1), '' order by i)
      into v_ww from (select gen_random_bytes(12) b) x, generate_series(0, 11) i;
    perform beheer_zet_wachtwoord(r.email, v_ww);
    docent_id := r.id; naam := r.naam; email := r.email; wachtwoord := v_ww;
    return next;
  end loop;
end $$;
revoke all on function maak_tijdelijke_wachtwoorden(uuid[]) from public, anon;
grant execute on function maak_tijdelijke_wachtwoorden(uuid[]) to authenticated;

-- Per docent: wachtwoord ingesteld ja/nee (alleen voor beheerders)
create or replace function beheer_wachtwoord_status()
returns table (email text, heeft_wachtwoord boolean, laatst_ingelogd timestamptz)
language sql stable security definer set search_path = public as $$
  select d.email,
         coalesce(u.encrypted_password is not null and u.encrypted_password <> '', false),
         u.last_sign_in_at
    from docenten d
    left join auth.users u on lower(u.email) = lower(d.email)
   where is_admin()
$$;
revoke all on function beheer_wachtwoord_status() from public, anon;
grant execute on function beheer_wachtwoord_status() to authenticated;
