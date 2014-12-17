GRANT USAGE ON *.* TO 'mymonitor'@'[MASTER_IP]' IDENTIFIED BY 'secret' WITH MAX_USER_CONNECTIONS 20;
grant usage, replication client on *.* to 'proxyadmin'@'[MASTER_IP]' identified by 'adminsecret';
GRANT USAGE ON *.* TO 'mymonitor'@'[SLAVE_IP]' IDENTIFIED BY 'secret' WITH MAX_USER_CONNECTIONS 20;
grant usage, replication client on *.* to 'proxyadmin'@'[SLAVE_IP]' identified by 'adminsecret';
