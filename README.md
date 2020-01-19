Lbry Mining Pool based on Yiimp

To install the pool you will need:
1. Ubuntu 16.04 VPS
2. Install Script

WARNINGS
- Use at your own risks.

The install Script will install the pool and all dependencies needed.

TO INSTALL:
1. Log in to VPS
2. Create new user - sudo adduser (username)
3. Add user to sudo group - sudo adduser (username) sudo
4. Log in to new user - sudo su (username)
5. cd ~/
6. `wget https://raw.githubusercontent.com/lbryio/pool/next/install.sh && chmod +x install.sh && ./install.sh`
7. Follow the instructions on the screen.
8. sudo bash screen-start.sh

This will setup the pool ready for coin daemons to be added.

You can find sample config files in web/serverconfig.sample.php and web/keys.sample.php


You need at least three backend shells (in screen) running these scripts:

	web/main.sh
	web/loop2.sh
	web/block.sh
	
This is done running the screen-start.sh script in the home folder.

Now you will need to edit the coin in the admin panel, this will be http://IP/site/ADMIN_ADDRESS_USED_WHILE_INSTALLING then go to Coins on the headers, Find LBRY Credits and click LBC.

Here you need to do the following:
1. Edit algo to lbry
2. Edit image to /images/coin-LBRY.png
3. Edit Daemon information to the following:
4. process name - lbrycrdd
5. Conf.folder - .lbrycrd
6. RPC Host - 127.0.0.1
7. RPC User - This is the Username at the end of the install script. 
8. RPC Password - This is the Password at the end of the install script.
9. RPC Type - POW
10. Edit Settings and tick the following boxes:
11. Enable
12. Auto Ready
13. Visable
14. Installed
15. Click Save

Once you have clicked save, you need to restart the lbry daemon in the VPS:
1. lbrycrd-cli stop
2. lbrycrdd -daemon

At the moment you will find other wallets active, you can click the install tick box on all of the ones that you are not using. I will update this at some point to remove them when installing.

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


Credits:

Thanks to globalzon to have released the initial Yaamp source code.
Thanks to tpruvot for updating the source code to yiimp.
Thanks to oakey22 for customising this for Lbry.

