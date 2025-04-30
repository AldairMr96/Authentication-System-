-- Insert roles
INSERT INTO roles (id_role, role_type) VALUES
(1, 'MANAGER'),
(2, 'USER'),
(3, 'DEVELOPER');

-- Insert Permissions
INSERT INTO permissions (id_permission, name_permission) VALUES
(1, 'CREATE'),
(2, 'READ'),
(3, 'UPDATE'),
(4, 'DELETE');

-- Insert roles and permissions
INSERT INTO role_permission (id_role_permission, id_role, id_permission) VALUES
(1, 1, 1), -- MANAGER puede CREATE_USER
(2, 1, 2), -- MANAGER puede READ_USER
(3, 1, 3), -- MANAGER puede UPDATE_USER
(4, 1, 4), -- MANAGER puede DELETE_USER
(5, 2, 2), -- USER puede READ_USER
(6, 3, 2), -- DEVELOPER puede READ_USER
(7, 3, 3), -- DEVELOPER puede UPDATE_USER
(8, 3, 1),
(9, 3, 4);
-- Insert users
INSERT INTO users (id_user, username, password, is_enable, account_no_expired, account_no_locked, creadential_no_expired, role_id_user) VALUES
--admin123--
(1, 'admin', '$2a$10$dhvbJXTxMSBnXudsnFN2uO0PViKrqVXTE811h4wLYe4AMWwd8LJXu', true, true, true, true, 1), -- Usuario admin con rol MANAGER
--user123
(2, 'user1', '$2a$10$1Qh.Bi2i1tF07pw3Fzooh.MiJr7z8uMlrcfD8.z80Pb4DXgCLqTt.', true, true, true, true, 2), -- Usuario user1 con rol USER
--dev123
(3, 'dev1', '$2a$10$/a9AIwnt6Tv6HspGcHn2wuhxpduSWMEKFQn9IEpBOzngOidFzXeLy', true, true, true, true, 3);   -- Usuario dev1 con rol DEVELOPER

