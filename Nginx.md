```
# Anti DNS Rebinding
server {
        listen                          443 ssl default_server;
        server_name                     _;

        ssl_verify_client               off;
        proxy_ssl_session_reuse         on;
        return                          444;
}
```