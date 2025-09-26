-- Users
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Courses
CREATE TABLE IF NOT EXISTS courses (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  event_date DATE NOT NULL,
  time_text TEXT NOT NULL DEFAULT 'TBD',
  location_text TEXT NOT NULL DEFAULT 'TBD',
  max_member INTEGER NOT NULL DEFAULT 30
);

-- Enrollments
CREATE TABLE IF NOT EXISTS enrollments (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  course_id TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, course_id)
);

-- Feedback
CREATE TABLE IF NOT EXISTS feedback (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  rating NUMERIC(2,1) NOT NULL CHECK (rating >= 1 AND rating <= 5),
  message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed
INSERT INTO courses (id, title, event_date, time_text, location_text, max_member)
VALUES
  ('c1', 'Bilingual Exchange · 双语交流（第1期）', DATE '2025-10-07', 'TBD', 'TBD', 30),
  ('c2', 'Bilingual Exchange · 双语交流（第2期）', DATE '2025-10-14', 'TBD', 'TBD', 30)
ON CONFLICT (id) DO NOTHING;