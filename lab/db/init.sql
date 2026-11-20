-- Lab database (stands in for the shared RDS cluster our WordPress hosts use). Synthetic credentials, lab only.
-- mysql_native_password because PHP 7.0 on the 16.04 lab host can't do caching_sha2_password.
CREATE USER IF NOT EXISTS 'wp'@'%' IDENTIFIED WITH mysql_native_password BY 'lab-only-password';
GRANT ALL PRIVILEGES ON `wp\_%`.* TO 'wp'@'%';
FLUSH PRIVILEGES;
