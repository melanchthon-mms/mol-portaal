-- Toegang per docent (Beheer → Klassen & gebruikers → Docenten → vinkje "Toegang").
--   Uit = deze docent kan op geen enkele manier inloggen (wachtwoord, Microsoft of code). Wachtwoord blijft bewaard.
--   Beheerders hebben altijd toegang (zo kan niemand zichzelf of alle beheerders buitensluiten).

alter table docenten add column if not exists toegang boolean not null default true;

create or replace function public.my_email()
 returns text language sql stable security definer set search_path to 'public'
as $function$
  with t as (
    select lower(nullif(auth.jwt() ->> 'email', '')) e,
           auth.jwt() -> 'app_metadata' ->> 'provider' p,
           coalesce((auth.jwt() ->> 'is_anonymous')::boolean, false) anon)
  select coalesce(
    (select e from t where not anon and e is not null
       and not exists (select 1 from docenten d where lower(d.email) = t.e and not d.toegang and not d.is_admin)
       and (
         (p = 'azure' and not exists (select 1 from leerlingen l where lower(l.email) = t.e and not l.sso))
         or (p = 'email' and exists (select 1 from docenten d where lower(d.email) = t.e and (d.is_admin or not d.sso))))),
    (select lower(coalesce(l.email, d.email)) from code_sessies c
       left join leerlingen l on l.id = c.leerling_id and not l.sso
       left join docenten d on d.id = c.docent_id and not d.sso and not d.is_admin and d.toegang
      where c.uid = auth.uid() and c.aangemaakt > now() - interval '12 hours'),
    '')
$function$;
