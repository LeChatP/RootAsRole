# Is a Linux system without root user possible ?

To make it short, not really. But you can design your system to never have to use the root user. This is what RootAsRole aims, and the exact purpose of Linux Capabilities. Let's consider you want a system without root user and you want to setup a webserver. Firstly, let's create the apache2 user and group:

```bash
dosr adduser apache2
```

We consider that we still use the default configuration of RootAsRole. Then, let's add a task to install apache2 with the apache2 user:

```bash
dosr chsr r r_root t install_apache2 add
dosr chsr r r_root t install_apache2 cmd whitelist add apt install apache2
dosr chsr r r_root t install_apache2 cmd whitelist add "apt upgrade( -y)? apache2"
dosr chsr r r_root t install_apache2 cred set --caps CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_NET_BIND_SERVICE,CAP_SETUID --setuid apache2 --setgid apache2
```

Then, let's add a task to start apache2 with the apache2 user:

```bash
dosr chsr r r_root t start_apache2 add
dosr chsr r r_root t start_apache2 cmd whitelist add "systemctl ((re)?start|stop) apache2"
dosr chsr r r_root t start_apache2 cmd whitelist add "service apache2 ((re)?start|stop)"
dosr chsr r r_root t install_apache2 cred set --caps CAP_NET_BIND_SERVICE,CAP_SETUID --setuid apache2 --setgid apache2
```

So now you can install and start apache2 with the apache2 user:

```bash
dosr apt install apache2
```

This should install apache2 configuration files owned by apache2 user and group. Then you can start apache2 with the apache2 user:

```bash
dosr systemctl start apache2
```