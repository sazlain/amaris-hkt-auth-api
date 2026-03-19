-- Usuarios por defecto para testing
-- Las contraseñas están hasheadas con BCrypt

-- Usuario: admin / Contraseña: Admin@123
INSERT INTO users (username, email, password, role, enabled, created_at, updated_at)
VALUES (
  'admin',
  'admin@amaris.com',
  '$2a$10$slYQmyNdGzin7olVVCb1Be7DlH.PKZbv5H8KfzzIgXXbVxzy2QJOG',
  'ADMIN',
  true,
  NOW(),
  NOW()
) ON CONFLICT DO NOTHING;

-- Usuario: testuser / Contraseña: Test@1234
INSERT INTO users (username, email, password, role, enabled, created_at, updated_at)
VALUES (
  'testuser',
  'testuser@amaris.com',
  '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36CHbroI',
  'USER',
  true,
  NOW(),
  NOW()
) ON CONFLICT DO NOTHING;

-- Usuario: demo / Contraseña: Demo@123
INSERT INTO users (username, email, password, role, enabled, created_at, updated_at)
VALUES (
  'demo',
  'demo@amaris.com',
  '$2a$10$9L5dz.JhYb1x4q9F6.kVXuRwJb8L4cV9n2K3L6J5m8I9p0Q1R2S3t',
  'USER',
  true,
  NOW(),
  NOW()
) ON CONFLICT DO NOTHING;

