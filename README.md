### What it does

The Foxpass RADIUS agent is a simple RADIUS server that authenticates against Foxpass's API on the backend.

It speaks a version of RADIUS that is not suitable for use on the open Internet.

Unlike the Foxpass RADIUS proxy, it has configuration parameters to enforce group membership and Duo 2-factor.

### How to install it

(Assuming Ubuntu; please create a pull request for other distros!)

* Install the pre-reqs
  * `pip install -r requirements.txt`
* Install the tool
  * `sudo cp foxpass-radius-agent.py /usr/local/bin/`
* Install the upstart script
  * `sudo cp upstart/foxpass-radius-agent.conf /etc/init/`
* Install the sample config file
  * `sudo cp foxpass-radius-agent.conf.sample /etc/foxpass-radius-agent.conf`
* Edit the configuration
  * `sudo vi /etc/foxpass-radius-agent.conf`
* Run it
  * `sudo service foxpass-radius-agent start`

SysV
=====

Script installation
------------
Install the start script
```
sudo mv sysv/foxpass-radius-agent /etc/init.d/foxpass-radius-agent
```

Script usage
------------

### Start ###

Starts the app.

    /etc/init.d/foxpass-radius-agent start

### Stop ###

Stops the app.

    /etc/init.d/foxpass-radius-agent stop

### Restart ###

Restarts the app.

    /etc/init.d/foxpass-radius-agent restart

### Status ###

Tells you whether the app is running. Exits with _0_ if it is and _1_
otherwise.

    /etc/init.d/foxpass-radius-agent status

Systemd
=====

Script installation
------------
Install the control script
```
sudo mv systemd/foxpass-radius-agent.service /lib/systemd/system/
sudo systemctl enable foxpass-radius-agent.service
```

Script usage
------------

### Start ###

Starts the app.

      sudo systemctl start foxpass-radius-agent

### Stop ###

Stops the app.

      sudo systemctl stop foxpass-radius-agent

### Restart ###

Restarts the app.

      sudo systemctl restart foxpass-radius-agent

### Status ###

Tells you some statistics about the process and its current state.

      sudo systemctl status foxpass-radius-agent

### Logs ###

Messaging handled by journald; access the output using journal

      journalctl -u foxpass-radius-agent.service
