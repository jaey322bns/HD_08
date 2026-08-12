-- ============================================================
-- Reusable Supabase Membership Template
-- 회원가입용 프로필 테이블 + 트리거 + RLS
-- 대상: index.html 의 PROFILE_TABLE = "site_member_profiles"
-- ============================================================

begin;

-- 1) 이 템플릿 전용 프로필 테이블
-- 기존 public.profiles 테이블을 건드리지 않도록 별도 이름을 사용합니다.
create table if not exists public.site_member_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  full_name text not null check (char_length(btrim(full_name)) between 2 and 50),
  phone text not null check (phone ~ '^01[016789][0-9]{7,8}$'),
  privacy_consent_at timestamptz not null default now(),
  site_code text not null default 'default',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.site_member_profiles is
'재사용형 회원가입 페이지 전용 프로필. auth.users와 1:1 연결. 이름/전화번호/동의시각 저장.';

comment on column public.site_member_profiles.phone is
'하이픈 없이 숫자만 저장. 예: 01012345678';

-- 2) RLS 활성화
alter table public.site_member_profiles enable row level security;

-- 브라우저의 익명 사용자는 프로필 테이블에 직접 접근하지 못하도록 차단합니다.
revoke all on table public.site_member_profiles from anon;

-- 로그인한 사용자는 자신의 프로필 조회/수정만 필요합니다.
revoke all on table public.site_member_profiles from authenticated;
grant select, update on table public.site_member_profiles to authenticated;

-- 기존 정책이 있으면 재실행 가능하도록 정리합니다.
drop policy if exists "site_member_select_own" on public.site_member_profiles;
drop policy if exists "site_member_update_own" on public.site_member_profiles;

create policy "site_member_select_own"
on public.site_member_profiles
for select
to authenticated
using ((select auth.uid()) = id);

create policy "site_member_update_own"
on public.site_member_profiles
for update
to authenticated
using ((select auth.uid()) = id)
with check ((select auth.uid()) = id);

-- 3) auth.users 신규 가입 시 프로필 자동 생성
-- 이 HTML 템플릿이 signup_source 메타데이터를 보낸 경우에만 실행되어
-- 프로젝트 내 다른 회원가입 흐름에 영향을 주지 않습니다.
create or replace function public.handle_site_member_signup()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_name text;
  v_phone text;
  v_site_code text;
  v_consent text;
begin
  v_name := btrim(coalesce(new.raw_user_meta_data ->> 'full_name', ''));
  v_phone := regexp_replace(coalesce(new.raw_user_meta_data ->> 'phone', ''), '[^0-9]', '', 'g');
  v_site_code := btrim(coalesce(new.raw_user_meta_data ->> 'site_code', 'default'));
  v_consent := lower(coalesce(new.raw_user_meta_data ->> 'privacy_consent', 'false'));

  if char_length(v_name) < 2 or char_length(v_name) > 50 then
    raise exception '회원 이름이 올바르지 않습니다.';
  end if;

  if v_phone !~ '^01[016789][0-9]{7,8}$' then
    raise exception '휴대전화 번호가 올바르지 않습니다.';
  end if;

  if v_consent <> 'true' then
    raise exception '필수 개인정보 수집·이용 동의가 필요합니다.';
  end if;

  insert into public.site_member_profiles (
    id,
    email,
    full_name,
    phone,
    privacy_consent_at,
    site_code
  )
  values (
    new.id,
    lower(coalesce(new.email, '')),
    v_name,
    v_phone,
    now(),
    nullif(v_site_code, '')
  )
  on conflict (id) do update
  set
    email = excluded.email,
    full_name = excluded.full_name,
    phone = excluded.phone,
    site_code = excluded.site_code,
    updated_at = now();

  return new;
end;
$$;

revoke all on function public.handle_site_member_signup() from public;

drop trigger if exists on_auth_user_created_site_member_profiles on auth.users;

create trigger on_auth_user_created_site_member_profiles
after insert on auth.users
for each row
when ((new.raw_user_meta_data ->> 'signup_source') = 'reusable-membership-v1')
execute function public.handle_site_member_signup();

-- 4) updated_at 자동 갱신
create or replace function public.set_site_member_updated_at()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

revoke all on function public.set_site_member_updated_at() from public;

drop trigger if exists set_site_member_profiles_updated_at on public.site_member_profiles;

create trigger set_site_member_profiles_updated_at
before update on public.site_member_profiles
for each row
execute function public.set_site_member_updated_at();

commit;

-- ============================================================
-- 실행 후 Supabase Dashboard에서 반드시 확인할 항목
--
-- Authentication > Providers > Email
--   - Email provider 활성화
--   - Confirm email 활성화 권장
--
-- Authentication > Password Security
--   - Minimum password length: 10 이상
--   - Required characters:
--     Digits + lowercase + uppercase + symbols (가장 강한 옵션)
--   - Pro 이상이라면 leaked password protection 사용 권장
--
-- Authentication > URL Configuration
--   - Site URL: 실제 GitHub Pages/서비스 주소
--   - Redirect URLs: 실제 서비스 URL 등록
--
-- 주의:
--   - sb_publishable_... 키만 브라우저에서 사용합니다.
--   - sb_secret_... / service_role 키는 절대로 HTML/JS에 넣지 마세요.
-- ============================================================
