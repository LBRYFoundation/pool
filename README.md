Lbry Mining Pool based on Yiimp

To install the pool you will need:
1. Ubuntu 16.04 VPS
2. Install Script

The install Script will install the pool and all dependencies needed.

TO INSTALL:
1. Log in to VPS
2. Create new user - sudo adduser (username)
3. Add user to sudo group - sudo adduser (username) sudo
4. Log in to new user - sudo su (username)
5. wget https://raw.githubusercontent.com/lbryio/pool/next/install.sh && chmod +x install.sh && ./install.sh
6. Follow the instructions on the screen.

This will setup the pool ready for coin daemons to be added.


Add your exchange API public and secret keys in these two separated files:

	/etc/yiimp/keys.php - fixed path in code
	web/serverconfig.php - use sample as base...

You can find sample config files in web/serverconfig.sample.php and web/keys.sample.php

This web application includes some command line tools, add bin/ folder to your path and type "yiimp" to list them, "yiimp checkup" can help to test your initial setup.
Future scripts and maybe the "cron" jobs will then use this yiic console interface.

You need at least three backend shells (in screen) running these scripts:

	web/main.sh
	web/loop2.sh
	web/block.sh

Start one stratum per algo using the run.sh script with the algo as parameter. For example, for x11:

	run.sh x11

Edit each .conf file with proper values.

Look at rc.local, it starts all three backend shells and all stratum processes. Copy it to the /etc folder so that all screen shells are started at boot up.

All your coin's config files need to blocknotify their corresponding stratum using something like:

	blocknotify=blocknotify yaamp.com:port coinid %s

On the website, go to http://server.com/site/adminRights to login as admin. You have to change it to something different in the code (web/yaamp/modules/site/SiteController.php). A real admin login may be added later, but you can setup a password authentification with your web server, sample for lighttpd:

	htpasswd -c /etc/yiimp/admin.htpasswd <adminuser>

and in the lighttpd config file:

	# Admin access
	$HTTP["url"] =~ "^/site/adminRights" {
	        auth.backend = "htpasswd"
	        auth.backend.htpasswd.userfile = "/etc/yiimp/admin.htpasswd"
	        auth.require = (
	                "/" => (
	                        "method" => "basic",
	                        "realm" => "Yiimp Administration",
	                        "require" => "valid-user"
	                )
	        )
	}

And finally remove the IP filter check in SiteController.php



There are logs generated in the /var/stratum folder and /var/log/stratum/debug.log for the php log.

More instructions coming as needed.


There a lot of unused code in the php branch. Lot come from other projects I worked on and I've been lazy to clean it up before to integrate it to yaamp. It's mostly based on the Yii framework which implements a lightweight MVC.

	http://www.yiiframework.com/


Credits:

Thanks to globalzon to have released the initial Yaamp source code.

--

You can support this project donating to tpruvot :

BTC : 1Auhps1mHZQpoX4mCcVL8odU81VakZQ6dR

