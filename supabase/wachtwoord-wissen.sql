-- Beheer: wachtwoord van een docent wissen (Klassen & gebruikers → Docenten → "Wachtwoord wissen").
--   Alleen e-mailaccount (geen Microsoft-koppeling): het hele account verdwijnt (sessies vervallen mee).
--   Ook Microsoft gekoppeld: alleen het wachtwoord en de e-mailkoppeling gaan weg; sessies worden beëindigd.
--   Niet voor beheerders (die beheren hun wachtwoord zelf bij Beheer → Meer).
create or replace function beheer_wis_wachtwoord(p_docent uuid) returns void
language plpgsql security definer set search_path = public as $$
declare
  v_email text;
  v_id uuid;
begin
  if not is_admin() then raise exception 'Alleen beheerders kunnen wachtwoorden wissen.'; end if;
  select lower(email) into v_email from docenten where id = p_docent and not is_admin;
  if v_email is null then raise exception 'Alleen voor docenten die geen beheerder zijn.'; end if;
  select id into v_id from auth.users where lower(email) = v_email;
  if v_id is null then return; end if;
  if exists (select 1 from auth.identities where user_id = v_id and provider <> 'email') then
    update auth.users set encrypted_password = '', updated_at = now() where id = v_id;
    delete from auth.identities where user_id = v_id and provider = 'email';
    delete from auth.sessions where user_id = v_id;
  else
    delete from auth.users where id = v_id;
  end if;
end $$;
revoke all on function beheer_wis_wachtwoord(uuid) from public, anon;
grant execute on function beheer_wis_wachtwoord(uuid) to authenticated;
