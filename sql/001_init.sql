-- 扩展
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- users：主键 uuid，邮箱唯一，存密码哈希
CREATE TABLE IF NOT EXISTS public.users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email           text NOT NULL,
  username        text,
  password_hash   text NOT NULL,
  email_verified  boolean NOT NULL DEFAULT false,
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_login_at   timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique_idx ON public.users (lower(email));
CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique_idx ON public.users (lower(username));

-- courses：两门课程示例
CREATE TABLE IF NOT EXISTS public.courses (
  id          bigserial PRIMARY KEY,
  title       text        NOT NULL,
  description text,
  start_time  timestamptz NOT NULL,
  end_time    timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_courses_start_time ON public.courses(start_time);

-- enrollments：用户-课程 多对多
CREATE TABLE IF NOT EXISTS public.enrollments (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid   NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  course_id  bigint NOT NULL REFERENCES public.courses(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, course_id)
);
CREATE INDEX IF NOT EXISTS idx_enroll_user   ON public.enrollments(user_id);
CREATE INDEX IF NOT EXISTS idx_enroll_course ON public.enrollments(course_id);

-- 预置两门课（时间请按需改）
INSERT INTO public.courses (title, description, start_time, end_time) VALUES
('InScope 课程 A', '入门体验课', '2025-10-05 10:00+10', '2025-10-05 12:00+10')
ON CONFLICT DO NOTHING;

INSERT INTO public.courses (title, description, start_time, end_time) VALUES
('InScope 课程 B', '进阶提高课', '2025-10-12 10:00+10', '2025-10-12 12:00+10')
ON CONFLICT DO NOTHING;