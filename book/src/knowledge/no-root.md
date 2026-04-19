# Is a Linux system without a root user possible?

Short answer: not really.

Practical answer: you can design operations so daily work does not require logging in as `root`. That is exactly the RootAsRole objective with Linux capabilities.

Example: preparing Apache management without direct root sessions.

First, create the service account:

```bash
dosr adduser apache2
```

Then create a task to install Apache with that account:

```bash
dosr chsr r r_root t install_apache2 add
dosr chsr r r_root t install_apache2 cmd whitelist add /usr/sbin/apt install apache2
dosr chsr r r_root t install_apache2 cmd whitelist add "/usr/sbin/apt ^upgrade( -y)? apache2$"
dosr chsr r r_root t install_apache2 cred set --caps CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_NET_BIND_SERVICE,CAP_SETUID --setuid apache2 --setgid apache2
```

Add another task to start/stop Apache:

```bash
dosr chsr r r_root t start_apache2 add
dosr chsr r r_root t start_apache2 cmd whitelist add "/usr/sbin/systemctl ^((re)?start|stop) apache2$"
dosr chsr r r_root t start_apache2 cmd whitelist add "/usr/bin/service ^apache2 ((re)?start|stop)$"
dosr chsr r r_root t install_apache2 cred set --caps CAP_NET_BIND_SERVICE,CAP_SETUID --setuid apache2 --setgid apache2
```

Now installation can be delegated through policy:

```bash
dosr apt install apache2
```

Then service control can also run through delegated tasks:

```bash
dosr systemctl start apache2
```